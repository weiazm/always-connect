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
            },
            Group { id: 2, name: "Off".into(), enabled: false, members: vec![Member { pattern: "d.example".into(), method: Some(PRESET_TRACE.into()), probe_host: None }], cidrs: vec![], expect: vec!["ZZ".into()] },
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
    let hook: ProbeHook = Arc::new(move |r: &ProbeRequest| {
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
    gate.write_all(b"{\"up\":{\"ifname\":\"utun9\"}}\n{\"check\":{\"group\":1,\"host\":\"a.example\"}}\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&line).unwrap(), serde_json::json!({"verdict":{"group":1,"ok":true}}));
    {
        let r = &seen.lock().unwrap()[0];
        assert_eq!(r.alpn, vec!["http/1.1".to_string(), ctl.marker()]);
        assert_eq!(r.interface, "utun9");
    }
    // Change the expected countries; the other member now blocks the group.
    config.groups[0].expect.pop();
    ctl.update(config.clone());
    for _ in 0..2 { line.clear(); reader.read_line(&mut line).unwrap(); }
    gate.write_all(b"{\"check\":{\"group\":1,\"host\":\"c.example\"}}\n").unwrap();
    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&line).unwrap()["verdict"]["ok"], false);
    let st: serde_json::Value = serde_json::from_str(&ctl.status_json()).unwrap();
    assert_eq!(st["running"], true);
    assert_eq!(st["groups"][0]["state"], "blocked");
    assert_eq!(st["records"][0]["host"], "c.example");
    assert!(st["records"][0]["ended"].is_null());
    // A disabled or unknown group is refused.
    gate.write_all(b"{\"check\":{\"group\":2,\"host\":\"d.example\"}}\n").unwrap();
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
    gate.write_all(b"{\"check\":{\"group\":1,\"host\":\"c.example\"}}\n").unwrap();
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
    let hook: ProbeHook = Arc::new(move |_| {
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
    gate.write_all(b"{\"up\":{\"ifname\":\"utun9\"}}\n{\"check\":{\"group\":1,\"host\":\"a.example\"}}\n").unwrap();
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
