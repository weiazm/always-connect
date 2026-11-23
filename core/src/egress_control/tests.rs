use super::*;

// Example names and fixture countries only (ZZ, YY are user-assigned codes).
fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
    Response { status, headers: headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), body: body.as_bytes().to_vec() }
}

fn method(id: &str) -> ProbeMethod {
    EgressConfig::default().method(id).expect("preset")
}

fn custom_json() -> ProbeMethod {
    ProbeMethod { id: "json".into(), name: "JSON".into(), url: "https://echo.example/geo".into(), head: false, extract: Extract { kind: ExtractKind::Json, key: "geo.country".into(), regex: None } }
}

fn cfg() -> EgressConfig {
    EgressConfig {
        block_unidentified_web:true,
        enabled: true,
        methods: vec![custom_json()],
        groups: vec![
            Group {
                id: 1,
                name: "Work".into(),
                enabled: true,
                members: vec![
                    Member { pattern: "a.example".into(), method: Some(PRESET_TRACE.into()), probe_host: None },
                    Member { pattern: "*.b.example".into(), method: Some(PRESET_CDN.into()), probe_host: Some("www.b.example".into()) },
                    Member { pattern: "c.example".into(), method: None, probe_host: None },
                ],
                cidrs: vec!["203.0.113.0/24".into()],
                expect: vec!["ZZ".into()],
                ..Group::default()
            },
            Group { id: 2, name: "Off".into(), enabled: false, members: vec![Member { pattern: "d.example".into(), method: Some(PRESET_TRACE.into()), probe_host: None }], cidrs: vec![], expect: vec!["ZZ".into()], ..Group::default() },
        ],
    }
}

#[test]
fn trace_answers_give_country_and_address() {
    let r = resp(200, &[], "fl=1\nip=198.51.100.7\nloc=zz\ncolo=SIN\n");
    assert_eq!(extract(&method(PRESET_TRACE), &r), Ok(("ZZ".into(), Some("198.51.100.7".into()))));
    assert!(extract(&method(PRESET_TRACE), &resp(404, &[], "not found")).is_err());
    assert!(extract(&method(PRESET_TRACE), &resp(200, &[], "<html>")).is_err());
}

#[test]
fn json_answers_follow_the_dot_path() {
    let r = resp(200, &[], r#"{"ip":"198.51.100.7","geo":{"country":"YY"}}"#);
    assert_eq!(extract(&custom_json(), &r), Ok(("YY".into(), Some("198.51.100.7".into()))));
    assert!(extract(&custom_json(), &resp(200, &[], "{}")).is_err());
}

#[test]
fn cdn_headers_name_the_node_airport() {
    let m = method(PRESET_CDN);
    assert_eq!(extract(&m, &resp(200, &[("cf-ray", "8a1b2c3d4e5f-SIN")], "")), Ok(("SG".into(), None)));
    assert_eq!(extract(&m, &resp(403, &[("x-amz-cf-pop", "NRT57-P3")], "")), Ok(("JP".into(), None)), "status does not matter for headers");
    assert_eq!(extract(&m, &resp(200, &[("x-served-by", "cache-iad-x1-IAD, cache-fra-y2-FRA")], "")), Ok(("DE".into(), None)));
    assert!(extract(&m, &resp(200, &[("server", "nginx")], "")).is_err());
    assert!(extract(&m, &resp(200, &[("cf-ray", "abc-QQQ")], "")).unwrap_err().contains("QQQ"), "unknown airport is reported, not guessed");
}

#[test]
fn a_regex_picks_the_code() {
    let m = ProbeMethod { id: "re".into(), name: "re".into(), url: "https://{host}/".into(), head: true, extract: Extract { kind: ExtractKind::Header, key: "x-node".into(), regex: Some(r"region=([a-z]{2})".into()) } };
    assert_eq!(extract(&m, &resp(200, &[("x-node", "id=7;region=zz")], "")), Ok(("ZZ".into(), None)));
    assert!(extract(&m, &resp(200, &[("x-node", "id=7")], "")).is_err());
}

#[test]
fn requests_are_https_only_and_name_the_site() {
    let (h, port, req) = build_request(&method(PRESET_TRACE), "a.example").unwrap();
    assert_eq!((h.as_str(), port), ("a.example", 443));
    assert!(req.starts_with("GET /cdn-cgi/trace HTTP/1.1\r\nHost: a.example\r\n"));
    assert!(req.ends_with("\r\n\r\n") && req.contains("Connection: close"));
    assert!(!req.to_ascii_lowercase().contains("cookie"), "no identity");
    let (_, _, head) = build_request(&method(PRESET_CDN), "a.example").unwrap();
    assert!(head.starts_with("HEAD / HTTP/1.1"));
    let mut m = method(PRESET_TRACE);
    m.url = "http://{host}/".into();
    assert!(build_request(&m, "a.example").is_err());
    m.url = "https://{host}:8443/x".into();
    assert_eq!(build_request(&m, "a.example").unwrap().1, 8443);
}

#[test]
fn setup_probe_reports_each_method_without_forwarding_a_redirect_or_identity() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let hook: ProbeHook = Arc::new(move |request, _peer| {
        captured.lock().unwrap().push(request.clone());
        let line = request.request.lines().next().unwrap();
        let reply: &[u8] = match line {
            "GET /cdn-cgi/trace HTTP/1.1" => b"HTTP/1.1 302 Found\r\nLocation: https://redirect.example/\r\n\r\n",
            "HEAD / HTTP/1.1" => b"HTTP/1.1 200 OK\r\nX-Served-By: cache-iad-x1-IAD\r\n\r\n",
            "GET /geo HTTP/1.1" => b"HTTP/1.1 200 OK\r\n\r\n{\"ip\":\"198.51.100.7\",\"geo\":{\"country\":\"YY\"}}",
            _ => panic!("unexpected request: {line}"),
        };
        Some(reply.into())
    });
    let results = probe_methods(&cfg(), "a.example", &hook, "fixture-marker", "utun42");
    assert_eq!(results.iter().map(|result| result.method.as_str()).collect::<Vec<_>>(),
               [PRESET_TRACE, PRESET_CDN, "json"]);
    assert!(results.iter().all(|result| result.host == "a.example"));
    assert!(results[0].country.is_none() && results[0].error.is_some());
    assert_eq!(results[1].country.as_deref(), Some("US"));
    assert_eq!(results[2].country.as_deref(), Some("YY"));
    assert_eq!(results[2].ip.as_deref(), Some("198.51.100.7"));

    let requests = requests.lock().unwrap();
    let mut hosts: Vec<_> = requests.iter().map(|request| request.host.as_str()).collect();
    hosts.sort_unstable();
    assert_eq!(hosts, ["a.example", "a.example", "echo.example"]);
    for request in requests.iter() {
        assert_eq!(request.alpn, ["http/1.1", "fixture-marker"]);
        assert_eq!(request.interface, "utun42");
        let headers: Vec<_> = request.request.lines().skip(1).filter_map(|line| line.split_once(':')).collect();
        assert_eq!(headers.iter().map(|(name, _)| *name).collect::<Vec<_>>(), ["Host", "Accept", "Connection"]);
    }
}

#[test]
fn chunked_bodies_are_joined() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nloc=Z\r\n2\r\nZ\n\r\n0\r\n\r\n";
    let r = parse_response(raw).unwrap();
    assert_eq!(r.body, b"loc=ZZ\n");
    assert!(parse_response(b"garbage").is_none());
}

#[test]
fn targets_follow_the_group_rules() {
    let c = cfg();
    let g = c.group(1).unwrap();
    // Every checkable member is probed even when the trigger has a method.
    let t = probe_targets(&c, g, Some("a.example"));
    assert_eq!(t.iter().map(|(h, m)| (h.as_str(), m.id.as_str())).collect::<Vec<_>>(), vec![("a.example", PRESET_TRACE), ("www.b.example", PRESET_CDN)]);
    // A wildcard member's site is probed with the name the connection used.
    let t = probe_targets(&c, g, Some("api.b.example"));
    assert_eq!(t[1].0, "api.b.example");
    // "Follow the group": the other checkable members are probed.
    let t = probe_targets(&c, g, Some("c.example"));
    assert_eq!(t.iter().map(|(h, _)| h.as_str()).collect::<Vec<_>>(), vec!["a.example", "www.b.example"]);
    // Triggered by an address only.
    assert_eq!(probe_targets(&c, g, None).len(), 2);
}

#[test]
fn decisions_fail_closed() {
    let g = cfg().groups[0].clone();
    let o = |c: Option<&str>| Observation { country: c.map(str::to_string), ..Default::default() };
    assert!(decide(&g, &[o(Some("ZZ")), o(Some("zz"))]));
    assert!(!decide(&g, &[o(Some("ZZ")), o(Some("YY"))]), "any member wrong blocks the group");
    assert!(!decide(&g, &[o(Some("ZZ")), o(None)]), "unreachable counts as wrong");
    assert!(!decide(&g, &[]), "nothing probed");
    let mut unlocked = g.clone();
    unlocked.expect.clear();
    assert!(!decide(&unlocked, &[o(Some("ZZ"))]), "no expected country yet");
}

#[test]
fn records_open_once_close_on_recovery_and_keep_ten() {
    let mut st = Status::default();
    let g = cfg().groups[0].clone();
    st.apply(&g, Some("a.example"), vec![], false, 1.0);
    st.apply(&g, Some("a.example"), vec![], false, 2.0);
    assert_eq!(st.records.len(), 1, "one record per block, not per check");
    st.apply(&g, Some("a.example"), vec![], true, 3.0);
    assert_eq!(st.records[0].ended, Some(3.0));
    assert_eq!(st.groups[0].state, "ok");
    for i in 0..30 {
        st.apply(&g, None, vec![], i % 2 == 0, 10.0 + i as f64);
    }
    assert_eq!(st.records.len(), MAX_RECORDS);
}

#[test]
fn gate_sees_enabled_groups_only() {
    let v = cfg().gate_groups();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0]["names"][1], "*.b.example");
    assert_eq!(v[0]["cidrs"][0], "203.0.113.0/24");
}

#[test]
fn patterns_match_like_the_gate() {
    assert!(pattern_matches("*.b.example", "x.b.example"));
    assert!(!pattern_matches("*.b.example", "b.example"));
    assert!(!pattern_matches("*.b.example", "xb.example"));
    assert!(pattern_matches("A.Example", "a.example."));
}

/// The controller end to end over its socket, with a scripted probe hook.
#[test]
fn controller_answers_a_gate() {
    let dir = std::env::temp_dir().join(format!("ac-egress-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let sock = dir.join("egress.sock");
    let seen: Arc<Mutex<Vec<ProbeRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let hook: ProbeHook = Arc::new(move |r: &ProbeRequest, _peer| {
        s2.lock().unwrap().push(r.clone());
        let loc = if r.host == "a.example" { "ZZ" } else { "YY" };
        Some(format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nip=198.51.100.7\nloc={loc}\n").into_bytes())
    });
    let mut config = cfg();
    config.groups[0].members[1].method = Some(PRESET_TRACE.into());
    config.groups[0].expect.push("YY".into());
    let ctl = Controller::start(&sock, config.clone(), hook.clone()).unwrap();
    let mut gate = UnixStream::connect(&sock).unwrap();
    gate.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reader = BufReader::new(gate.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let first: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(first["probe_alpn"], ctl.marker());
    gate.write_all(b"{\"up\":{\"ifname\":\"utun9\"}}\n{\"check\":{\"group\":1,\"hostConfirmed\":true,\"host\":\"a.example\",\"ip\":\"192.0.2.19\",\"port\":443,\"requestId\":1}}\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    let v:serde_json::Value=serde_json::from_str(&line).unwrap();
    assert_eq!(v["verdict"]["ok"],true); assert_eq!(v["verdict"]["direct"],true);
    assert_eq!(v["verdict"]["group"],1);assert_eq!(v["verdict"]["requestId"],1);
    assert!(v["verdict"]["evidenceAtMs"].as_u64().is_some());
    {
        let r = &seen.lock().unwrap()[0];
        assert_eq!(r.alpn, vec!["http/1.1".to_string(), ctl.marker()]);
        assert_eq!(r.interface, "utun9");
    }
    // Change the expected countries; the other member now blocks the group.
    config.groups[0].expect.pop();
    ctl.update(config.clone());
    for _ in 0..2 { line.clear(); reader.read_line(&mut line).unwrap(); }
    gate.write_all(b"{\"check\":{\"group\":1,\"hostConfirmed\":true,\"host\":\"c.example\",\"ip\":\"192.0.2.19\",\"port\":443,\"requestId\":2}}\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&line).unwrap()["verdict"]["ok"], false);
    let st: serde_json::Value = serde_json::from_str(&ctl.status_json()).unwrap();
    assert_eq!(st["running"], true);
    assert_eq!(st["groups"][0]["state"], "blocked");
    assert_eq!(st["records"][0]["host"], "c.example");
    assert!(st["records"][0]["ended"].is_null());
    // A disabled or unknown group is refused.
    gate.write_all(b"{\"check\":{\"group\":2,\"host\":\"d.example\",\"ip\":\"192.0.2.19\",\"port\":443,\"requestId\":3}}\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&line).unwrap()["verdict"]["ok"], false);
    // Trust the observed country. The live update reaches the gate.
    config.groups[0].expect.push("YY".into());
    ctl.update(config);
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("probe_alpn"));
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert!(line.contains("invalidate"));
    // The next flow on the same connection is released after trusting the
    // observed country. Read back the original record rather than a new one.
    gate.write_all(b"{\"check\":{\"group\":1,\"hostConfirmed\":true,\"host\":\"c.example\",\"ip\":\"192.0.2.19\",\"port\":443,\"requestId\":4}}\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&line).unwrap()["verdict"]["ok"], true);
    let recovered: serde_json::Value = serde_json::from_str(&ctl.status_json()).unwrap();
    assert_eq!(recovered["groups"][0]["state"], "ok");
    assert_eq!(recovered["records"].as_array().unwrap().len(), 1);
    assert_eq!(recovered["records"][0]["started"], st["records"][0]["started"]);
    assert!(recovered["records"][0]["ended"].is_number());
    // Set-up probing runs every method.
    let all = probe_methods(&cfg(), "a.example", &hook, &ctl.marker(), "utun9");
    assert_eq!(all.len(), preset_methods().len() + 1);
    drop(ctl);
    assert!(!sock.exists(), "socket removed on stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_probe_started_before_rule_change_cannot_release_a_flow() {
    let dir = std::env::temp_dir().join(format!("ac-verdict-{:x}", random_u64()));
    std::fs::create_dir(&dir).unwrap();
    let sock = dir.join("egress.sock");
    let (entered, started) = std::sync::mpsc::channel();
    let (finish, released) = std::sync::mpsc::channel();
    let released = Mutex::new(released);
    let hook: ProbeHook = Arc::new(move |_, _peer| {
        entered.send(()).unwrap();
        released.lock().unwrap().recv_timeout(Duration::from_secs(3)).ok()?;
        Some(b"HTTP/1.1 200 OK\r\n\r\nloc=ZZ\n".to_vec())
    });
    let mut config = cfg();
    config.groups[0].members.truncate(1);
    let ctl = Controller::start(&sock, config.clone(), hook).unwrap();
    let mut gate = UnixStream::connect(&sock).unwrap();
    gate.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut reader = BufReader::new(gate.try_clone().unwrap());
    let mut line = String::new();
    assert!(reader.read_line(&mut line).unwrap() > 0);
    gate.write_all(b"{\"up\":{\"ifname\":\"utun9\"}}\n{\"check\":{\"group\":1,\"hostConfirmed\":true,\"host\":\"a.example\",\"ip\":\"192.0.2.19\",\"port\":443,\"requestId\":5}}\n").unwrap();
    started.recv_timeout(Duration::from_secs(3)).unwrap();
    config.groups[0].expect = vec!["YY".into()];
    ctl.update(config);
    for _ in 0..2 { line.clear(); assert!(reader.read_line(&mut line).unwrap() > 0); }
    finish.send(()).unwrap();
    line.clear();
    gate.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
    assert!(reader.read_line(&mut line).is_err(), "stale verdict must never reach the gate: {line}");
    assert!(ctl.shared.state.lock().unwrap().status.records.is_empty());
    drop(ctl);
    std::fs::remove_dir_all(&dir).unwrap();
}

fn target_check(id: u64, ip: &str, host: Option<&str>) -> CheckMsg {
    CheckMsg { host_confirmed:true, group: 1, host: host.map(str::to_owned), ip: ip.parse().unwrap(), port: 443.try_into().unwrap(),
        request_id: id.try_into().unwrap() }
}

fn observations(plan: &[Target], wrong: &[IpAddr]) -> Vec<(Target, Observation)> {
    plan.iter().cloned().map(|target| {
        let bad = target.peer.is_some_and(|(ip, _)| wrong.contains(&ip));
        let obs = Observation { country: Some(if bad { "YY" } else { "ZZ" }.into()), ..Default::default() };
        (target, obs)
    }).collect()
}

#[test]
fn pinned_failure_must_itself_recover_even_if_another_address_passes() {
    let mut cfg = cfg();
    cfg.groups[0].members.truncate(1);
    let group = &cfg.groups[0];
    let a = target_check(1, "192.0.2.10", Some("a.example"));
    let b = target_check(2, "192.0.2.11", Some("a.example"));
    let mut state = Failures::default();
    let old_b = state.plan(&cfg, group, &b);
    let plan_a = state.plan(&cfg, group, &a);
    assert_eq!(plan_a[0].peer, Some((a.ip, 443)));
    assert!(!state.evaluate(group, 0, &observations(&plan_a, &[a.ip])));
    assert!(state.evaluate(group, 0, &observations(&old_b, &[])), "B can pass independently of A");
    assert!(!state.evaluate(group, 0, &observations(&plan_a, &[])), "old A cannot clear newer A failure");
    let direct_b = state.plan(&cfg, group, &b);
    assert_eq!(direct_b.len(), 1);
    assert_eq!(direct_b[0].peer.unwrap().0, b.ip);
    assert_eq!(state.observed_failures().len(), 1);
    let follow = target_check(3, "192.0.2.13", Some("follow.example"));
    let retry = state.plan(&cfg, group, &follow);
    assert!(retry.iter().any(|t| t.peer == Some((a.ip, 443))));
    assert!(!state.evaluate(group, state.generation, &observations(&retry, &[a.ip])));
    assert!(state.evaluate(group, state.generation, &observations(&retry, &[])));
    assert!(state.observed_failures().is_empty());
}

#[test]
fn failed_target_limit_never_drops_a_failure_to_authorize_a_healthy_site() {
    let mut cfg = cfg();
    cfg.groups[0].members.truncate(1);
    let group = &cfg.groups[0];
    let mut state = Failures::default();
    for last in 1..=9 {
        let request = target_check(last as u64, &format!("192.0.2.{last}"), Some("a.example"));
        let plan = state.plan(&cfg, group, &request);
        assert!(!state.evaluate(group, state.generation, &recheck::unconfirmed(&plan, "timeout")));
    }
    assert!(state.overflowed());
    let mut edited = cfg.clone();
    edited.groups[0].name = "Renamed".into();
    state.reset_if_edited(&cfg, &edited, &edited.groups[0]);
    assert!(state.overflowed());
    edited.groups[0].expect = vec!["YY".into()];
    state.reset_if_edited(&cfg, &edited, &edited.groups[0]);
    assert!(!state.overflowed());
    assert_eq!(state.plan(&cfg, group, &target_check(10, "192.0.2.10", Some("a.example"))).len(), 1);
}

#[test]
fn third_party_results_cannot_authorize_or_block_and_unnamed_checks_keep_their_tls_identity() {
    let mut cfg = cfg();
    cfg.groups[0].members[2].method = Some("json".into());
    assert!(!custom_json().is_direct());
    let mut embedded = custom_json();
    embedded.url = "https://{host}.example.invalid/check".into();
    assert!(!embedded.is_direct());
    embedded.url = "https://{host}:8443/check".into();
    assert!(embedded.is_direct());
    let check = target_check(1, "2001:db8::a", None);
    let state = Failures::default();
    let plan = state.plan(&cfg, &cfg.groups[0], &check);
    assert!(plan.iter().all(|t| t.method.id != "json"));
    let proxy = plan.iter().find(|t| t.peer.is_some()).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let output = seen.clone();
    let hook: ProbeHook = Arc::new(move |r, _peer| {
        output.lock().unwrap().push((r.host.clone(), r.connect_ip, r.request.clone()));
        if r.host == "a.example" { None } else { Some(b"HTTP/1.1 200 OK\r\ncf-ray: abc-SIN\r\n\r\n".to_vec()) }
    });
    let obs = proxy.observe(&hook, "marker", "utun42");
    assert_eq!(obs.evidence.as_deref(), Some("proxy"));
    assert_eq!(obs.peer_address, Some(check.ip));
    assert_eq!(obs.host, "www.b.example");
    let calls = seen.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|(name, peer, bytes)| *peer == Some(check.ip)
        && bytes.contains(&format!("Host: {name}\r\n"))));
    cfg.groups[0].members.retain(|m| m.method.as_deref() == Some("json"));
    assert!(!cfg.has_direct_method(&cfg.groups[0]));
    assert!(state.plan(&cfg, &cfg.groups[0], &check).is_empty());
}

#[test]
fn late_permission_cannot_override_a_gate_timeout_and_a_new_destination_rechecks_the_old_one() {
    let dir = std::env::temp_dir().join(format!("ac-path-verdict-{:x}", random_u64()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("controller");
    let a: IpAddr = "192.0.2.10".parse().unwrap();
    let b: IpAddr = "192.0.2.20".parse().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let wrong_a = Arc::new(AtomicBool::new(false));
    let log = seen.clone();
    let bad = wrong_a.clone();
    let hook: ProbeHook = Arc::new(move |req, _peer| {
        assert_eq!(req.host, "a.example");
        assert!(req.request.contains("Host: a.example\r\n"));
        let ip = req.connect_ip.unwrap_or("192.0.2.22".parse().unwrap());
        log.lock().unwrap().push(ip);
        let loc = if ip == a && bad.load(Ordering::SeqCst) { "YY" } else { "ZZ" };
        Some(format!("HTTP/1.1 200 OK\r\n\r\nloc={loc}\n").into_bytes())
    });
    let mut cfg = cfg();
    cfg.groups[0].members.truncate(1);
    let ctl = Controller::start(&sock, cfg.clone(), hook).unwrap();
    let attach = || {
        let gate = UnixStream::connect(&sock).unwrap();
        gate.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut r = BufReader::new(gate);
        let mut text = String::new();
        r.read_line(&mut text).unwrap();
        writeln!(r.get_mut(), "{}", serde_json::json!({"up":{"ifname":"utun9"}})).unwrap();
        r
    };
    fn send(r: &mut BufReader<UnixStream>, kind: &str, ip: IpAddr, id: u64, host: &str) {
        writeln!(r.get_mut(), "{}", serde_json::json!({kind:{"group":1,"hostConfirmed":true,"host":host,"ip":ip,
                 "port":443,"requestId":id}})).unwrap();
    }
    fn verdict_for(r: &mut BufReader<UnixStream>, ip: IpAddr, id: u64, host: &str) -> bool {
        send(r, "check", ip, id, host);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["verdict"]["requestId"], id);
        v["verdict"]["ok"].as_bool().unwrap()
    }
    let mut r = attach();
    assert!(verdict_for(&mut r, a, 1, "a.example"));
    // The accept reply and the gate's timeout may cross on the control socket.
    send(&mut r, "timedOut", a, 1, "a.example");
    wrong_a.store(true, Ordering::SeqCst);
    assert!(verdict_for(&mut r, b, 2, "a.example"));
    assert!(!verdict_for(&mut r, b, 3, "follow.example"));
    assert!(seen.lock().unwrap().contains(&b));
    drop(r);
    let mut r = attach();
    assert!(!verdict_for(&mut r, b, 1, "follow.example"), "gate restart alone cannot clear the failed peer");
    wrong_a.store(false, Ordering::SeqCst);
    seen.lock().unwrap().clear();
    assert!(verdict_for(&mut r, b, 2, "follow.example"));
    let mut checked = seen.lock().unwrap().clone();
    checked.sort();
    assert_eq!(checked, [a,"192.0.2.22".parse::<IpAddr>().unwrap()]);
    let st: serde_json::Value = serde_json::from_str(&ctl.status_json()).unwrap();
    assert_eq!(st["groups"][0]["state"], "ok");
    assert!(st["records"][0]["ended"].is_number());
    drop(r);
    drop(ctl);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_resolved_member_failure_is_rechecked_on_its_observed_peer_without_becoming_direct_evidence() {
    let mut cfg = cfg();
    cfg.groups[0].members.truncate(1);
    let check = target_check(1, "192.0.2.80", Some("follow.example"));
    let group = &cfg.groups[0];
    let mut failed = Failures::default();
    let first = failed.plan(&cfg, group, &check);
    let a: IpAddr = "192.0.2.10".parse().unwrap();
    let b: IpAddr = "192.0.2.20".parse().unwrap();
    let healthy_a = Arc::new(AtomicBool::new(false));
    let healthy = healthy_a.clone();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sequence = calls.clone();
    let hook: ProbeHook = Arc::new(move |r, peer| {
        let ip = r.connect_ip.unwrap_or_else(|| if sequence.fetch_add(1, Ordering::SeqCst) == 0 { a } else { b });
        *peer = Some(ip);
        let country = if ip == a && !healthy.load(Ordering::SeqCst) { "YY" } else { "ZZ" };
        Some(format!("HTTP/1.1 200 OK\r\n\r\nloc={country}\n").into_bytes())
    });
    let run = |targets: Vec<Target>| targets.into_iter().map(|t| {
        let observation = t.observe(&hook, "marker", "utun9");
        (t, observation)
    }).collect::<Vec<_>>();
    assert!(!failed.evaluate(group, 0, &run(first)));
    let next = failed.plan(&cfg, group, &check);
    assert!(next.iter().any(|t| t.peer == Some((a,443)) && !t.direct_flow()));
    assert!(!failed.evaluate(group, failed.generation, &run(next)));
    let obs = failed.observed_failures();
    assert_eq!(obs.len(), 1);
    assert_eq!(obs[0].evidence.as_deref(), Some("member"));
    assert_eq!(obs[0].peer_address, Some(a));
    healthy_a.store(true, Ordering::SeqCst);
    let next = failed.plan(&cfg, group, &check);
    assert!(failed.evaluate(group, failed.generation, &run(next)));
}

#[test]
fn explicit_recheck_and_country_approval_use_only_the_current_verified_failure() {
    let dir = std::env::temp_dir().join(format!("ac-recheck-{:x}", random_u64()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg = cfg();
    cfg.groups[0].members.truncate(1);
    let ok = Arc::new(AtomicBool::new(false));
    let valid = ok.clone();
    let hook: ProbeHook = Arc::new(move |request, actual| {
        *actual = request.connect_ip;
        let value = if valid.load(Ordering::SeqCst) {"ZZ"} else {"YY"};
        Some(format!("HTTP/1.1 200 OK\r\n\r\nloc={value}\n").into_bytes())
    });
    let socket = dir.join("ctl");
    let ctl = Controller::start(&socket,cfg.clone(),hook).unwrap();
    let mut reader = BufReader::new(UnixStream::connect(&socket).unwrap());
    reader.get_ref().set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    writeln!(reader.get_mut(), "{}",serde_json::json!({"up":{"ifname":"utun9"}})).unwrap();
    writeln!(reader.get_mut(),"{}",serde_json::json!({"check":{"requestId":1,"group":1,"hostConfirmed":true,"ip":"192.0.2.9","port":443,"host":"a.example"}})).unwrap();
    line.clear(); reader.read_line(&mut line).unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&line).unwrap()["verdict"]["ok"], false);
    let (started,evidence) = {
        let state = ctl.shared.state.lock().unwrap();
        let incident = &state.status.records[0];
        (incident.started, incident.observed[0].clone())
    };
    let mut forged = evidence.clone(); forged.peer_address = Some("192.0.2.99".parse().unwrap());
    assert!(ctl.allow_country(&cfg,1,started,"YY",&forged).is_none());
    assert!(ctl.allow_country(&cfg,1,started,"XX",&evidence).is_none());
    assert!(ctl.allow_country(&cfg,1,started-1.0,"YY",&evidence).is_none());
    forged = evidence.clone(); forged.evidence = Some("proxy".into());
    assert!(ctl.allow_country(&cfg,1,started,"YY",&forged).is_none());
    let updated = ctl.allow_country(&cfg,1,started,"YY",&evidence).unwrap();
    assert_eq!(updated.groups[0].expect, ["ZZ","YY"]);
    assert!(ctl.allow_country(&cfg,1,started,"YY",&evidence).is_none(), "outdated settings cannot be overwritten");
    let run = ctl.recheck_job(1).unwrap();
    assert!(ctl.recheck_job(1).is_none(), "coalesce duplicate explicit rechecks");
    assert!(run());
    assert!(ctl.recheck_job(1).is_none());
    assert!(ctl.allow_country(&updated,1,started,"YY",&evidence).is_none(), "closed incident cannot authorize a country");
    drop(reader); drop(ctl); std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn only_current_direct_wrong_country_evidence_can_hint_dns() {
    let cfg = cfg();
    let group = &cfg.groups[0];
    let a: std::net::Ipv4Addr = "192.0.2.10".parse().unwrap();
    let b: std::net::Ipv4Addr = "192.0.2.11".parse().unwrap();
    let mut failed = Failures::default();
    let check = target_check(1, &a.to_string(), Some("a.example"));
    let t = failed.plan(&cfg, group, &check)[0].clone();
    let hook: ProbeHook = Arc::new(|_, _| None);
    let mut o = t.observe(&hook, "marker","utun9");
    o.error = None;
    o.country = Some("YY".into());
    assert!(!failed.evaluate(group,0,&[(t.clone(),o.clone())]));
    assert_eq!(failed.wrong_ipv4(group,"a.example",&[a,b]),[a]);
    assert!(failed.wrong_ipv4(group,"other.example",&[a,b]).is_empty());
    failed.invalidate_dns();
    assert!(failed.wrong_ipv4(group,"a.example",&[a,b]).is_empty());
    o.country = None;
    o.error = Some("timeout".into());
    assert!(!failed.evaluate(group,failed.generation,&[(t,o)]));
    assert!(failed.wrong_ipv4(group,"a.example",&[a,b]).is_empty());
    assert!(!failed.pending_targets().is_empty(), "gate still rechecks an unconfirmed target");
}

#[test]
fn denial_totals_are_idempotent_and_accumulate_across_gate_peers() {
    let mut state = ControlState {
        dns_evidence:Default::default(), warm:Default::default(), source_policies: HashMap::new(), config: cfg(), status: Status::default(), peer: None, peer_id: 1, epoch: 1,
        checks: HashMap::new(), failures: HashMap::new(), peer_counts: HashMap::new(), unknown_counts:HashMap::new(),internal_cidrs:Vec::new(), on_peer_loss: None,
    };
    let report = |n| serde_json::from_value(serde_json::json!({"group":1,"count":n,"hosts":[{"host":"a.example","count":n}],
        "lastHost":"a.example","hostsTruncated":false})).unwrap();
    state.denied_counts(vec![report(4)]);
    state.denied_counts(vec![report(4)]);
    state.denied_counts(vec![report(2)]);
    assert_eq!(state.status.groups[0].blocked_count,4);
    state.disconnect();
    state.denied_counts(vec![report(3)]);
    let j=serde_json::to_value(&state.status.groups[0]).unwrap();
    assert_eq!(j["blockedCount"],7);
    assert_eq!(j["sites"][0]["blockedCount"],7);
    assert_eq!(j["lastBlockedHost"],"a.example");
    assert!(j["lastBlockedCountry"].is_null());
}

#[test]
fn approval_never_confuses_the_site_peer_with_the_reported_exit_range() {
    let cfg=cfg();
    let mut group=cfg.groups[0].clone();
    group.exit_range_check=true;
    group.exit_ranges=vec!["198.51.100.0/24".into()];
    let pol=crate::egress_source::SourcePolicy::from_config(true,&group.exit_ranges).unwrap();
    let mut v=Observation { host:"a.example".into(), method:"trace".into(), evidence:Some("direct".into()),
        country:Some("ZZ".into()), ip:Some("203.0.113.8".into()),peer_address:Some("198.51.100.21".parse().unwrap()),..Default::default() };
    assert_eq!(failure_reason(&group,Some(&pol),&v),Some("exit-range-mismatch"));
    v.ip=Some("198.51.100.99".into());
    assert_eq!(failure_reason(&group,Some(&pol),&v),None);
    v.evidence=Some("proxy".into());
    assert_eq!(failure_reason(&group,Some(&pol),&v),Some("exit-ip-unavailable"));
    v.country=Some("YY".into());
    assert_eq!(failure_reason(&group,Some(&pol),&v),Some("country-mismatch"));
    assert!(!approvable_source("198.51.0.0/16","198.51.100.99".parse().unwrap()));
    assert!(approvable_source("2001:db8:1::/64","2001:db8:1::a".parse().unwrap()));
    assert!(!approvable_source("2001:db8::/32","2001:db8:1::a".parse().unwrap()));
}

#[test]
fn unknown_web_exceptions_require_current_counted_endpoint_and_never_replace_a_protected_rule() {
    let dir = std::env::temp_dir().join(format!("ac-unknown-control-{:x}", random_u64()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("ctl");
    let ctl = Controller::start(&socket,cfg(),Arc::new(|_,_|None)).unwrap();
    let mut reader = BufReader::new(UnixStream::connect(&socket).unwrap());
    reader.get_ref().set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut line=String::new();reader.read_line(&mut line).unwrap();
    let frame=serde_json::from_str::<serde_json::Value>(&line).unwrap();
    assert_eq!(frame["blockUnidentifiedWeb"],true);
    let announce=|count|serde_json::json!({"unknownWeb":[{"address":"198.51.100.7","port":443,"count":count,"lastReason":"ech"},
        {"address":"203.0.113.1","port":443,"count":1}]});
    writeln!(reader.get_mut(),"{}",serde_json::json!({"up":{"ifname":"utun9"}})).unwrap();
    writeln!(reader.get_mut(),"{}",announce(2)).unwrap();
    writeln!(reader.get_mut(),"{}",announce(2)).unwrap();
    let deadline=std::time::Instant::now()+Duration::from_secs(2);
    let status=loop {
        let s:serde_json::Value=serde_json::from_str(&ctl.status_json()).unwrap();
        if s["unknownWebCount"]==3 {break s}
        assert!(std::time::Instant::now()<deadline);std::thread::sleep(Duration::from_millis(5));
    };
    let records=status["unknownWeb"].as_array().unwrap();
    let ip="198.51.100.7".parse().unwrap();
    assert_eq!(records[0]["lastReason"], "ech");
    assert!(records[1].get("lastReason").is_none(), "legacy frames do not imply ECH");
    let token=records[0]["approvalId"].as_str().unwrap();
    assert!(!ctl.unknown_exception(ip,8443,true,token));
    assert!(!ctl.unknown_exception(ip,443,true,"old"));
    assert!(!ctl.unknown_exception("203.0.113.1".parse().unwrap(),443,true,records[1]["approvalId"].as_str().unwrap()));
    assert!(ctl.unknown_exception(ip,443,true,token));
    line.clear();reader.read_line(&mut line).unwrap();
    let frame:serde_json::Value=serde_json::from_str(&line).unwrap();
    assert_eq!(frame["unknownWebExceptions"],serde_json::json!([{"address":ip,"port":443}]));
    line.clear();reader.read_line(&mut line).unwrap();assert!(line.contains("invalidate"));
    assert!(ctl.unknown_exception(ip,443,false,token));
    line.clear();reader.read_line(&mut line).unwrap();
    let frame:serde_json::Value=serde_json::from_str(&line).unwrap();
    assert_eq!(frame["unknownWebExceptions"],serde_json::json!([]));
    line.clear();reader.read_line(&mut line).unwrap();
    ctl.session_internal_routes("0.0.0.0/0,198.51.0.0/16,198.51.100.0/24,2001:db8:1::/64");
    line.clear();reader.read_line(&mut line).unwrap();
    let frame:serde_json::Value=serde_json::from_str(&line).unwrap();
    assert_eq!(frame["unknownWebInternalCidrs"],serde_json::json!(["198.51.100.0/24","2001:db8:1::/64"]));
    drop(reader);drop(ctl);std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn range_confirmation_is_bound_to_the_live_exit_ip_and_cannot_expand_country_trust() {
    let dir = std::env::temp_dir().join(format!("ac-source-trust-{:x}", random_u64()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg=cfg();
    cfg.groups[0].exit_range_check=true;
    cfg.groups[0].exit_ranges=vec!["198.51.100.1/32".into()];
    let ctl=Controller::start(&dir.join("ctl"),cfg.clone(),Arc::new(|_,_|None)).unwrap();
    let request=target_check(1,"192.0.2.5",Some("a.example"));
    let (hold,_other)=UnixStream::pair().unwrap();
    let observe=|exit:&str| {
        let mut state=ctl.shared.state.lock().unwrap();
        let group=cfg.groups[0].clone();
        let failed=state.failures.entry(group.id).or_default();
        let generation=failed.generation;
        let target=failed.plan(&cfg,&group,&request).remove(0);
        let obs=Observation{host:"a.example".into(),method:PRESET_TRACE.into(),country:Some("ZZ".into()),
            evidence:Some("direct".into()),peer_address:Some(request.ip),ip:Some(exit.into()),..Default::default()};
        assert!(!state.record(&group,Some("a.example"),generation,vec![(target,obs)]));
        let current=state.status.groups[0].observed[0].clone();
        assert_eq!(current.failure_reason.as_deref(),Some("exit-range-mismatch"));
        (state.status.records[0].started,current)
    };
    {
        let mut state=ctl.shared.state.lock().unwrap();
        state.peer=Some(hold);state.status.interface="utun9".into();
    }
    let (started,old)=observe("203.0.113.5");
    let (same,current)=observe("203.0.113.6");
    assert_eq!(started,same);
    assert_ne!(old.approval_id,current.approval_id);
    assert!(ctl.approve(&cfg,1,started,"203.0.113.0/24",true,&old).is_none());
    assert!(ctl.approve(&cfg,1,started,"203.0.0.0/16",true,&current).is_none());
    assert!(ctl.approve(&cfg,1,started,"192.0.2.5/32",true,&current).is_none());
    let updated=ctl.approve(&cfg,1,started,"203.0.113.6/32",true,&current).unwrap();
    assert_eq!(updated.groups[0].exit_ranges,["198.51.100.1/32","203.0.113.6/32"]);
    assert_eq!(updated.groups[0].expect,cfg.groups[0].expect);
    assert!(ctl.approve(&updated,1,started,"203.0.113.0/24",true,&current).is_none());
    drop(ctl);std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn dns_inferred_name_uses_dependent_evidence_and_slow_results_keep_the_original_time() {
    let cfg=cfg();
    let mut q=target_check(1,"192.0.2.5",Some("a.example"));
    q.host_confirmed=false;
    let failed=Failures::default();
    let plan=failed.plan(&cfg,&cfg.groups[0],&q);
    assert!(plan.iter().all(|t|!t.direct_flow()));
    assert!(plan.iter().any(|t|t.peer==Some((q.ip,443))));
    q.host_confirmed=true;
    let target=failed.plan(&cfg,&cfg.groups[0],&q).remove(0);
    let hook:ProbeHook=Arc::new(|req,peer| {
        *peer=req.connect_ip;
        std::thread::sleep(Duration::from_millis(1050));
        Some(b"HTTP/1.1 200 OK\r\n\r\nloc=ZZ\n".to_vec())
    });
    let obs=target.observe(&hook,"marker","utun9");
    assert_eq!(obs.country.as_deref(),Some("ZZ"));
    assert!(!fresh_evidence(obs.evidence_at_ms.unwrap()),"response parsing must not refresh a slow probe");
}

#[test]
fn delivered_dns_stream_scopes_withdrawals_and_fences_loss_across_epoch_updates() {
    use crate::dns_forwarder::{DeliveredDns, DeliveredDnsKind, DeliveredDnsValue};
    use crate::egress_gate::evidence_clock_ms;
    let dir = std::env::temp_dir().join(format!("ac-dns-{:x}", random_u64()));
    std::fs::create_dir(&dir).unwrap();
    let config = cfg();
    let routes = config.protected_routes();
    let sock = dir.join("ctl");
    let ctl = Controller::start(&sock, config, Arc::new(|_, _| None)).unwrap();
    let mut reader = BufReader::new(UnixStream::connect(&sock).unwrap());
    reader.get_ref().set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    fn frame(reader: &mut BufReader<UnixStream>) -> serde_json::Value {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
    assert!(frame(&mut reader)["groups"].is_array());
    writeln!(reader.get_mut(), "{}", serde_json::json!({"up":{"ifname":"utun7"}})).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while ctl.shared.state.lock().unwrap().status.interface != "utun7" {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    ctl.set_dns_epoch(Some(7));
    std::thread::sleep(Duration::from_millis(3));
    let now = evidence_clock_ms().unwrap();
    let mut answer = DeliveredDns {
        epoch: 7, started_at_ms: now, observed_at_ms: now, name: "ordinary.example".into(),
        kind: DeliveredDnsKind::Ech, qtype: 65, incomplete: false, scope_known: false,
        values: vec![DeliveredDnsValue { value: "public.example".into(), ttl: 600 }],
    };
    ctl.delivered_dns(&answer, "retired", &routes);
    ctl.delivered_dns(&answer, "utun7", &routes);
    let first = frame(&mut reader)["dnsReset"].as_u64().unwrap();
    let update = frame(&mut reader);
    assert_eq!(update["dnsEvidence"]["generation"], first);
    assert_eq!(update["dnsEvidence"]["observedAtMs"], now);
    assert_eq!(update["dnsEvidence"]["values"][0]["ttl"], 300);
    answer.incomplete = true;
    answer.scope_known = true;
    answer.values.clear();
    answer.qtype = 64;
    ctl.delivered_dns(&answer, "utun7", &routes);
    let withdrawal = frame(&mut reader);
    assert_eq!(withdrawal["dnsEvidence"]["generation"], first);
    assert_eq!(withdrawal["dnsEvidence"]["qtype"], 64);
    assert_eq!(withdrawal["dnsEvidence"]["values"], serde_json::json!([]));

    // The same error on a protected name could hide an outstanding address.
    answer.name = "a.example".into();
    ctl.delivered_dns(&answer, "utun7", &routes);
    let reset = frame(&mut reader)["dnsReset"].as_u64().unwrap();
    assert!(reset > first);
    answer.name = "ordinary.example".into();
    answer.scope_known = false;
    ctl.delivered_dns(&answer, "utun7", &routes);
    ctl.set_dns_epoch(Some(8));
    assert!(frame(&mut reader)["dnsReset"].as_u64().unwrap() > reset);
    answer.incomplete = false;
    ctl.delivered_dns(&answer, "utun7", &routes);
    answer.epoch = 8;
    std::thread::sleep(Duration::from_millis(3));
    answer.started_at_ms = evidence_clock_ms().unwrap();
    answer.observed_at_ms = answer.started_at_ms;
    ctl.delivered_dns(&answer, "utun7", &routes);
    ctl.invalidate();
    assert_eq!(frame(&mut reader), serde_json::json!({"invalidate":true}));
    drop(reader);
    drop(ctl);
    std::fs::remove_dir_all(dir).unwrap();
}
