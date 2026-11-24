use super::*;
use crate::egress_gate::{Gate, GateConfig, Out, Step, Verdict};
use serde_json::{json, Value};
use std::time::Instant;

// Example names, documentation addresses and user-assigned country codes
// (ZZ, YY) only.

fn resp(status: u16, body: &str) -> Response {
    Response { status, headers: Vec::new(), body: body.as_bytes().to_vec() }
}

fn rule(id: u32, sites: &[&str], expect: &[&str]) -> Group {
    Group {
        id, name: format!("Rule {id}"), enabled: true,
        sites: sites.iter().map(|s| s.to_string()).collect(),
        expect: expect.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

fn cfg() -> EgressConfig {
    EgressConfig { enabled: true, groups: vec![Group { unverified: Unverified::Allow, ..rule(1, &["a.example"], &["ZZ"]) }, Group { enabled: false, ..rule(2, &["d.example"], &["ZZ"]) }] }
}

#[test]
fn trace_answers_give_country_and_address() {
    assert_eq!(read_trace(&resp(200, "fl=1\nip=198.51.100.7\nloc=zz\ncolo=XYZ\n")), Ok(("ZZ".into(), Some("198.51.100.7".into()))));
    assert_eq!(read_trace(&resp(200, "loc=ZZ\nip=not-an-address\n")), Ok(("ZZ".into(), None)));
    assert!(read_trace(&resp(404, "not found")).is_err());
    assert!(read_trace(&resp(200, "<html>")).is_err());
    assert!(read_trace(&resp(200, "loc=ZZZ\n")).is_err());
    assert!(trace_request("a.example").starts_with("GET /cdn-cgi/trace HTTP/1.1\r\nHost: a.example\r\n"));
}

#[test]
fn chunked_bodies_are_joined() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nloc=\r\n2\r\nZZ\r\n0\r\n\r\n";
    let r = parse_response(raw).unwrap();
    assert_eq!(r.body, b"loc=ZZ");
}

#[test]
fn rules_are_sites_and_countries() {
    assert!(cfg().valid());
    assert!(cfg().active());
    let mut no_country = cfg();
    no_country.groups[0].expect.clear();
    assert!(!no_country.valid(), "an enabled rule with sites needs a country");
    no_country.groups[0].enabled = false;
    assert!(no_country.valid(), "a paused rule may be unfinished");
    for bad in [&["not a host"][..], &["localhost"], &["a..example"]] {
        let mut c = cfg();
        c.groups[0].sites = bad.iter().map(|s| s.to_string()).collect();
        assert!(!c.valid(), "{bad:?}");
    }
    let mut lower = cfg();
    lower.groups[0].expect = vec!["zz".into()];
    assert!(!lower.valid());
    let mut twice = cfg();
    twice.groups[1].id = 1;
    assert!(!twice.valid());
    let mut many = cfg();
    many.groups = (0..17).map(|i| rule(i, &["a.example"], &["ZZ"])).collect();
    assert!(!many.valid());
    let off = EgressConfig { enabled: false, ..cfg() };
    assert!(!off.active() && off.site_groups().is_empty());
    assert_eq!(cfg().site_groups(), vec![SiteGroup { id: 1, sites: vec!["a.example".into()] }]);
}

#[test]
fn rules_saved_with_website_members_become_sites() {
    let old: EgressConfig = serde_json::from_value(json!({
        "enabled": true, "blockUnidentifiedWeb": true, "methods": [],
        "groups": [{"id": 3, "name": "Old", "enabled": true, "expect": ["ZZ"], "cidrs": ["203.0.113.0/24"],
            "members": [{"pattern": "a.example"}, {"pattern": "*.a.example"}, {"pattern": "*.B.example", "method": "trace"},
                        {"pattern": "geosite:example"}]}]
    })).unwrap();
    assert_eq!(old.groups[0].sites, vec!["a.example".to_string(), "b.example".into()]);
    assert!(old.valid());
    let saved = serde_json::to_value(&old).unwrap();
    assert_eq!(saved, json!({"enabled": true, "groups": [{"id": 3, "name": "Old", "enabled": true,
        "sites": ["a.example", "b.example"], "expect": ["ZZ"], "unverified": "whenWrong"}]}));
    let explicit: Group = serde_json::from_value(json!({"id": 4, "sites": ["c.example"], "members": [{"pattern": "a.example"}]})).unwrap();
    assert_eq!(explicit.sites, vec!["c.example".to_string()], "sites win over old members");
}

#[test]
fn records_open_once_close_on_recovery_and_keep_ten() {
    let mut st = Status::default();
    let g = rule(1, &["a.example"], &["ZZ"]);
    let wrong = Observation { host: "a.example".into(), country: Some("YY".into()), ..Default::default() };
    let right = Observation { country: Some("ZZ".into()), ..wrong.clone() };
    st.apply(&g, &wrong, vec![wrong.clone()], 1.0);
    st.apply(&g, &wrong, vec![wrong.clone()], 2.0);
    assert_eq!(st.records.len(), 1);
    assert_eq!(st.groups[0].state, "blocked");
    assert_eq!(serde_json::to_value(&st.groups[0].sites[0]).unwrap()["state"], "blocked");
    st.apply(&g, &right, Vec::new(), 3.0);
    assert_eq!(st.records[0].ended, Some(3.0));
    assert_eq!(st.groups[0].state, "ok");
    for i in 0..12 {
        st.apply(&g, &wrong, vec![wrong.clone()], 10.0 + i as f64);
        st.apply(&g, &right, Vec::new(), 10.5 + i as f64);
    }
    assert_eq!(st.records.len(), MAX_RECORDS);
}

// ------------------------------------------------------------- controller

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!("ac-egress-{}-{}", std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Probes answer with the country set for each server address.
fn exits(map: &[(&str, Option<&str>)]) -> (ProbeHook, Arc<Mutex<Vec<ProbeRequest>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let map: HashMap<IpAddr, Option<String>> = map.iter().map(|(ip, c)| (ip.parse().unwrap(), c.map(str::to_string))).collect();
    let hook: ProbeHook = Arc::new(move |r: &ProbeRequest, peer| {
        log.lock().unwrap().push(r.clone());
        *peer = r.connect_ip;
        let country = map.get(&r.connect_ip?)?.as_ref()?;
        Some(format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nip=192.0.2.200\nloc={country}\n").into_bytes())
    });
    (hook, seen)
}

struct Peer {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Peer {
    fn connect(sock: &Path) -> (Peer, Value) {
        let stream = UnixStream::connect(sock).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut peer = Peer { reader: BufReader::new(stream.try_clone().unwrap()), stream };
        let first = peer.read();
        peer.send(json!({"up": {"ifname": "utun9"}}));
        (peer, first)
    }

    fn send(&mut self, frame: Value) {
        writeln!(self.stream, "{frame}").unwrap();
    }

    fn read(&mut self) -> Value {
        let mut line = String::new();
        assert_ne!(self.reader.read_line(&mut line).unwrap(), 0);
        serde_json::from_str(&line).unwrap()
    }

    fn check(&mut self, group: u32, host: &str, ip: &str, id: u64) -> Value {
        self.send(json!({"check": {"group": group, "host": host, "ip": ip, "port": 443, "requestId": id}}));
        let answer = self.read();
        assert_eq!(answer["verdict"]["requestId"], id);
        answer["verdict"].clone()
    }
}

fn status(ctl: &Controller) -> Value {
    serde_json::from_str(&ctl.status_json()).unwrap()
}

#[test]
fn the_controller_checks_each_connections_own_server() {
    let dir = TestDirectory::new();
    let sock = dir.0.join("egress.sock");
    let (hook, seen) = exits(&[("192.0.2.1", Some("ZZ")), ("192.0.2.2", Some("YY")), ("192.0.2.3", None)]);
    let ctl = Controller::start(&sock, cfg(), hook).unwrap();
    let (mut gate, first) = Peer::connect(&sock);
    assert_eq!(first, json!({"probe_alpn": ctl.marker(), "groups": [{"id": 1, "sites": ["a.example"]}]}));

    let allowed = gate.check(1, "www.a.example", "192.0.2.1", 1);
    assert_eq!(allowed["result"], "allow");
    assert!(allowed["evidenceAtMs"].as_u64().is_some_and(|at| at > 0));
    {
        let r = &seen.lock().unwrap()[0];
        assert_eq!((r.host.as_str(), r.connect_ip, r.port), ("www.a.example", Some("192.0.2.1".parse().unwrap()), 443));
        assert_eq!(r.alpn, vec!["http/1.1".to_string(), ctl.marker()]);
        assert_eq!(r.interface, "utun9");
        assert!(r.request.starts_with("GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.a.example\r\n"));
    }
    assert_eq!(status(&ctl)["groups"][0]["state"], "ok");

    // Another server of the same site exits elsewhere: only it is blocked.
    assert_eq!(gate.check(1, "a.example", "192.0.2.2", 2)["result"], "block");
    let st = status(&ctl);
    assert_eq!(st["groups"][0]["state"], "blocked");
    assert_eq!(st["groups"][0]["observed"][0]["peerAddress"], "192.0.2.2");
    assert_eq!(st["groups"][0]["observed"][0]["country"], "YY");
    assert!(st["groups"][0]["observed"][0]["approvalId"].is_string());
    assert_eq!(st["records"][0]["host"], "a.example");
    assert!(st["records"][0]["ended"].is_null());
    assert_eq!(gate.check(1, "a.example", "192.0.2.1", 3)["result"], "allow");
    assert_eq!(status(&ctl)["groups"][0]["state"], "blocked", "the wrong server is still known");
    assert_eq!(gate.check(1, "b.a.example", "192.0.2.2", 31)["result"], "block");
    let st = status(&ctl);
    assert_eq!(st["records"].as_array().unwrap().len(), 1, "one record per block episode");
    assert_eq!(st["records"][0]["observed"], st["groups"][0]["observed"], "the record lists the current wrong exits");
    assert_eq!(st["records"][0]["observed"].as_array().unwrap().len(), 2);

    // Unreadable exit: best effort, let through and counted.
    assert_eq!(gate.check(1, "a.example", "192.0.2.3", 4)["result"], "unverified");
    assert_eq!(status(&ctl)["groups"][0]["unverifiedCount"], 1);

    // Paused, unknown or uncovered: refused without probing.
    let probes = seen.lock().unwrap().len();
    assert_eq!(gate.check(2, "d.example", "192.0.2.1", 5)["result"], "block");
    assert_eq!(gate.check(9, "a.example", "192.0.2.1", 6)["result"], "block");
    assert_eq!(gate.check(1, "b.example", "192.0.2.1", 7)["result"], "block");
    assert_eq!(seen.lock().unwrap().len(), probes);

    // Denial counts from the gate.
    gate.send(json!({"denied": [{"group": 1, "count": 2, "hosts": [{"host": "a.example", "count": 2}], "lastHost": "a.example"}]}));
    gate.send(json!({"denied": [{"group": 1, "count": 2, "hosts": [{"host": "a.example", "count": 2}], "lastHost": "a.example"}]}));
    assert_eq!(gate.check(1, "a.example", "192.0.2.1", 8)["result"], "allow");
    let st = status(&ctl);
    assert_eq!(st["groups"][0]["blockedCount"], 2, "cumulative reports are not counted twice");
    assert_eq!(st["groups"][0]["lastBlockedHost"], "a.example");
    assert_eq!(st["groups"][0]["lastBlockedCountry"], "YY");
    drop(ctl);
    assert!(!sock.exists(), "socket removed on stop");
}

#[test]
fn approving_a_country_and_rechecking_clear_a_block() {
    let dir = TestDirectory::new();
    let sock = dir.0.join("egress.sock");
    let (hook, _) = exits(&[("192.0.2.2", Some("YY"))]);
    let ctl = Controller::start(&sock, cfg(), hook).unwrap();
    let (mut gate, _) = Peer::connect(&sock);
    assert_eq!(gate.check(1, "a.example", "192.0.2.2", 1)["result"], "block");
    let st = status(&ctl);
    let record = st["records"][0].clone();
    let evidence: Observation = serde_json::from_value(st["groups"][0]["observed"][0].clone()).unwrap();
    let started = record["started"].as_f64().unwrap();

    // A recheck probes the same server again; still wrong.
    let job = ctl.recheck_job(1).expect("a failing server to recheck");
    assert!(ctl.recheck_job(1).is_none(), "one recheck at a time");
    assert!(job());
    assert_eq!(status(&ctl)["groups"][0]["state"], "blocked");
    assert_eq!(status(&ctl)["groups"][0]["observed"][0]["approvalId"], st["groups"][0]["observed"][0]["approvalId"],
               "the same wrong exit keeps its approval");

    // Only the current observation, record and configuration approve.
    let other = Observation { peer_address: Some("192.0.2.9".parse().unwrap()), ..evidence.clone() };
    assert!(ctl.allow_country(&cfg(), 1, started, "YY", &other).is_none());
    assert!(ctl.allow_country(&cfg(), 1, started + 1.0, "YY", &evidence).is_none());
    assert!(ctl.allow_country(&cfg(), 1, started, "XX", &evidence).is_none());
    assert!(ctl.allow_country(&EgressConfig::default(), 1, started, "YY", &evidence).is_none());
    let updated = ctl.allow_country(&cfg(), 1, started, "YY", &evidence).unwrap();
    assert_eq!(updated.groups[0].expect, vec!["ZZ".to_string(), "YY".into()]);
    assert_eq!(gate.read()["groups"][0]["id"], 1);
    assert_eq!(gate.read(), json!({"invalidate": true}));
    let st = status(&ctl);
    assert_eq!(st["groups"][0]["state"], "ok");
    assert!(st["records"][0]["ended"].is_number());
    assert!(ctl.recheck_job(1).is_none(), "nothing left to recheck");
    assert_eq!(gate.check(1, "a.example", "192.0.2.2", 2)["result"], "allow");
}

#[test]
fn editing_a_rule_drops_failures_it_no_longer_covers_and_retires_running_checks() {
    let dir = TestDirectory::new();
    let sock = dir.0.join("egress.sock");
    let (hook, _) = exits(&[("192.0.2.2", Some("YY"))]);
    let ctl = Controller::start(&sock, cfg(), hook).unwrap();
    let (mut gate, _) = Peer::connect(&sock);
    assert_eq!(gate.check(1, "a.example", "192.0.2.2", 1)["result"], "block");
    let mut edited = cfg();
    edited.groups[0].sites = vec!["c.example".into()];
    ctl.update(edited.clone());
    assert_eq!(gate.read(), json!({"probe_alpn": ctl.marker(), "groups": [{"id": 1, "sites": ["c.example"]}]}));
    assert_eq!(gate.read(), json!({"invalidate": true}));
    assert_eq!(status(&ctl)["groups"][0]["state"], "ok");
    edited.groups[0].enabled = false;
    ctl.update(edited);
    gate.read();
    gate.read();
    assert!(status(&ctl)["groups"].as_array().unwrap().is_empty());
}

#[test]
fn a_probe_started_before_a_rule_change_cannot_release_a_connection() {
    let dir = TestDirectory::new();
    let sock = dir.0.join("egress.sock");
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let (resume, resume_rx) = std::sync::mpsc::channel::<()>();
    let resume_rx = Mutex::new(resume_rx);
    let hook: ProbeHook = Arc::new(move |_: &ProbeRequest, _| {
        let _ = entered_tx.send(());
        let _ = resume_rx.lock().unwrap().recv_timeout(Duration::from_secs(5));
        Some(b"HTTP/1.1 200 OK\r\n\r\nloc=ZZ\n".to_vec())
    });
    let ctl = Controller::start(&sock, cfg(), hook).unwrap();
    let (mut gate, _) = Peer::connect(&sock);
    gate.send(json!({"check": {"group": 1, "host": "a.example", "ip": "192.0.2.1", "port": 443, "requestId": 1}}));
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(status(&ctl)["checking"], json!([1]));
    ctl.invalidate();
    resume.send(()).unwrap();
    assert_eq!(gate.read(), json!({"invalidate": true}));
    gate.stream.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let mut line = String::new();
    assert!(gate.reader.read_line(&mut line).is_err(), "no verdict after the invalidation: {line}");
}

/// The gate and the controller together, over the real socket.
#[test]
fn a_gate_and_its_controller_release_only_allowed_exits() {
    let dir = TestDirectory::new();
    let sock = dir.0.join("egress.sock");
    let (hook, _) = exits(&[("198.51.100.1", Some("ZZ")), ("198.51.100.2", Some("YY")), ("198.51.100.3", None)]);
    let ctl = Controller::start(&sock, cfg(), hook).unwrap();
    let (mut peer, first) = Peer::connect(&sock);
    let groups: Vec<SiteGroup> = serde_json::from_value(first["groups"].clone()).unwrap();
    let mut gate = Gate::new(GateConfig { probe_alpn: ctl.marker().into_bytes(), ..GateConfig::default() }, ProtectedSites::new(&groups));
    let now = Instant::now();
    let connect = |gate: &mut Gate, peer: &mut Peer, last: u8, sport: u16, host: &str| -> Vec<Out> {
        let tcp = |flags: u8, seq: u32, payload: &[u8]| {
            let mut p = vec![0u8; 40];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
            p[9] = 6;
            p[12..20].copy_from_slice(&[10, 0, 0, 2, 198, 51, 100, last]);
            p[20..22].copy_from_slice(&sport.to_be_bytes());
            p[22..24].copy_from_slice(&443u16.to_be_bytes());
            p[24..28].copy_from_slice(&seq.to_be_bytes());
            p[32] = 0x50;
            p[33] = flags;
            p.extend_from_slice(payload);
            p
        };
        assert_eq!(gate.outbound(&tcp(0x02, 1, &[]), now), Step::Forward);
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        assert_eq!(gate.outbound(&tcp(0x18, 2, request.as_bytes()), now), Step::Consumed);
        let out = gate.drain();
        let [Out::Check { group, host, destination, request_id }] = out.as_slice() else { panic!("{out:?}") };
        let (group, request_id) = (*group, *request_id);
        let answer = peer.check(group, host, &destination.ip().to_string(), request_id.get());
        let result = match answer["result"].as_str() {
            Some("allow") => Verdict::Allow { evidence_at_ms: answer["evidenceAtMs"].as_u64().unwrap() },
            Some("unverified") => Verdict::Unverified,
            _ => Verdict::Block,
        };
        gate.verdict(group, request_id, result, now);
        let mut out = Vec::new();
        for action in gate.drain() {
            match action {
                Out::SendChecked(id) => gate.send_checked(id, now, |packets| {
                    out.extend(packets.iter().cloned().map(Out::ToTunnel));
                    true
                }),
                other => out.push(other),
            }
        }
        out
    };
    assert!(matches!(connect(&mut gate, &mut peer, 1, 40001, "a.example").as_slice(), [Out::ToTunnel(_)]));
    assert!(matches!(connect(&mut gate, &mut peer, 2, 40002, "www.a.example").as_slice(), [Out::ToHost(_)]));
    assert!(matches!(connect(&mut gate, &mut peer, 3, 40003, "a.example").as_slice(), [Out::ToTunnel(_)]));
    let st = status(&ctl);
    assert_eq!((st["groups"][0]["state"].as_str(), st["groups"][0]["unverifiedCount"].as_u64()), (Some("blocked"), Some(1)));
}


#[test]
fn unknown_exits_follow_each_rules_policy_and_never_approve_a_nameless_server() {
    let mut config = cfg();
    config.groups[0].sites.push("192.0.2.0/24".into());
    config.groups[0].unverified = Unverified::WhenWrong;
    let allow_wrong = Arc::new(AtomicBool::new(false));
    let probes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hook: ProbeHook = {
        let allow_wrong = allow_wrong.clone();
        let probes = probes.clone();
        Arc::new(move |request, _| {
            probes.fetch_add(1, Ordering::Relaxed);
            match request.host.as_str() {
                "wrong.example" => {
                    let country = if allow_wrong.load(Ordering::Relaxed) { "ZZ" } else { "YY" };
                    Some(format!("HTTP/1.1 200 OK\r\n\r\nloc={country}\n").into_bytes())
                },
                _ => None,
            }
        })
    };
    let dir = TestDirectory::new();
    let path = dir.0.join("control");
    let ctl = Controller::start(&path, config.clone(), hook).unwrap();
    let (mut gate, _) = Peer::connect(&path);
    assert_eq!(gate.check(1, "", "192.0.2.3", 1)["result"], "unverified");
    assert_eq!(probes.load(Ordering::Relaxed), 0);
    assert_eq!(gate.check(1, "wrong.example", "192.0.2.2", 2)["result"], "block");
    assert_eq!(gate.check(1, "", "192.0.2.3", 3)["result"], "block");
    assert_eq!(status(&ctl)["groups"][0]["observed"].as_array().unwrap().len(), 1);
    allow_wrong.store(true, Ordering::Relaxed);
    assert!(ctl.recheck_job(1).unwrap()());
    assert_eq!(gate.check(1, "", "192.0.2.3", 4)["result"], "unverified");
    assert_eq!(status(&ctl)["groups"][0]["unverifiedCount"], 2);
    assert!(status(&ctl)["records"][0]["ended"].is_number());

    config.groups[0].unverified = Unverified::Block;
    ctl.update(config.clone());
    assert!(gate.read()["groups"].is_array());
    assert_eq!(gate.read()["invalidate"], true);
    assert_eq!(gate.check(1, "", "192.0.2.3", 5)["result"], "block");
    let status_before = status(&ctl);
    let observation = &status_before["groups"][0]["observed"][0];
    assert_eq!(observation["host"], "");
    assert_eq!(observation["peerAddress"], "192.0.2.3");
    assert!(observation["country"].is_null() && observation["approvalId"].is_null());
    assert!(ctl.recheck_job(1).unwrap()());
    assert_eq!(probes.load(Ordering::Relaxed), 2);
    assert_eq!(status(&ctl)["groups"][0]["state"], "blocked");

    config.groups[0].unverified = Unverified::Allow;
    ctl.update(config);
    assert!(gate.read()["groups"].is_array());
    assert_eq!(gate.read()["invalidate"], true);
    assert_eq!(gate.check(1, "", "192.0.2.3", 6)["result"], "unverified");
    assert_eq!(gate.check(1, "", "198.51.100.3", 7)["result"], "block", "outside every range");
    assert!(ctl.recheck_job(1).is_none());
    assert_eq!(status(&ctl)["groups"][0]["state"], "ok");
}

#[test]
fn a_wrong_cloudflare_entry_is_bypassed_by_one_verified_for_the_name() {
    let dir = TestDirectory::new();
    let sock = dir.0.join("egress.sock");
    let (hook, seen) = exits(&[("104.16.0.1", Some("ZZ")), ("104.16.0.2", Some("YY"))]);
    let config = EgressConfig { enabled: true, groups: vec![Group { unverified: Unverified::WhenWrong, ..rule(1, &["a.example"], &["ZZ"]) }] };
    let ctl = Controller::start(&sock, config, hook).unwrap();
    let (mut gate, _) = Peer::connect(&sock);
    let right: std::net::Ipv4Addr = "104.16.0.1".parse().unwrap();
    let wrong: std::net::Ipv4Addr = "104.16.0.2".parse().unwrap();
    assert_eq!(gate.check(1, "www.a.example", "104.16.0.1", 1)["result"], "allow");
    assert_eq!(ctl.steer("www.a.example", &[right]), None, "a good answer stays as it is");
    assert_eq!(gate.check(1, "x.a.example", "104.16.0.2", 2)["result"], "block");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while status(&ctl)["groups"][0]["state"] != "ok" {
        assert!(std::time::Instant::now() < deadline, "no verified entry found: {}", ctl.status_json());
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(seen.lock().unwrap().iter().any(|r| r.host == "x.a.example" && r.connect_ip == Some(IpAddr::V4(right))),
            "the search probes the name itself at the other entry");
    assert_eq!(status(&ctl)["groups"][0]["steered"], json!(["x.a.example"]));
    assert!(status(&ctl)["records"][0]["ended"].is_number(), "the bypassed wrong entry no longer holds the block");
    assert_eq!(ctl.steer("x.a.example", &[wrong]), Some(vec![right]));
    assert_eq!(ctl.steer("b.example", &[wrong]), None, "only protected names");
    assert_eq!(gate.check(1, "x.a.example", "104.16.0.2", 3)["result"], "block", "the gate still checks the wrong entry");
    ctl.invalidate();
    assert_eq!(ctl.steer("x.a.example", &[wrong]), None, "a network change forgets the exits");
}
