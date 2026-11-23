use super::*;
use crate::egress_control::{
    Controller, EgressConfig, GateGroup, Group, Member, ProbeHook, ProtectedRoutes, PRESET_TRACE,
};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const FOLLOW: &str = "follow.example";
const FIRST: &str = "first.example";
const SECOND: &str = "second.example";
const INDEPENDENT: &str = "independent.example";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ac-gate-{:x}-{nonce:x}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn member(pattern: &str, check: bool) -> Member {
    Member {
        pattern: pattern.into(),
        method: check.then(|| PRESET_TRACE.into()),
        probe_host: None,
    }
}

fn control_read(socket: &mut BufReader<UnixStream>) -> Value {
    let mut line = String::new();
    assert_ne!(socket.read_line(&mut line).unwrap(), 0);
    serde_json::from_str(&line).unwrap()
}

fn decide_held_flow(
    gate: &mut Gate,
    socket: &mut BufReader<UnixStream>,
    group: GroupId,
    host: Option<&str>,
    now: Instant,
) -> Vec<Out> {
    let mut id = None;
    for action in gate.drain() {
        let frame = match action {
            Out::Warm {group,host,destination} => json!({"warm":{"group":group,"host":host,
                "ip":destination.ip(),"port":destination.port()}}),
            Out::Check { group: requested, host: name, host_confirmed, destination, request_id } => {
                assert_eq!(requested, group);
                assert_eq!(name.as_deref(), host);
                assert!(id.replace(request_id).is_none());
                json!({"check":{"group":group,"host":host,"hostConfirmed":host_confirmed,
                    "ip":destination.ip(),"port":destination.port(),"requestId":request_id}})
            }
            other => panic!("unexpected action {other:?}"),
        };
        writeln!(socket.get_mut(), "{}",frame).unwrap();
    }
    let request_id=id.expect("expected a destination check");
    let response = control_read(socket);
    let verdict = &response["verdict"];
    assert_eq!(verdict["group"], group);
    assert_eq!(verdict["requestId"].as_u64(), Some(request_id.get()));
    let answer = match (verdict["ok"].as_bool().unwrap(), verdict["direct"].as_bool()) {
        (false, _) => Verdict::Block,
        (true, Some(true)) => Verdict::AllowDirect,
        (true, _) => Verdict::AllowDependent,
    };
    gate.verdict(group, request_id, answer, verdict["evidenceAtMs"].as_u64(), now);
    drain(gate)
}

#[derive(Clone, Copy)]
enum ProbeResult {
    Normal,
    ChangedCountry,
    MissingCountry,
    NoAnswer,
}

// Drive the same classifier, packet decisions, controller and Unix-socket
// protocol as the tunnel binary. Only the IP packet source and HTTPS
// responses are fixtures, so this doesn't require routes, pf or a VPN.
#[test]
fn controller_and_gate_admit_reject_and_recover_ipv6_flows() {
    let directory = TestDirectory::new();
    let config = EgressConfig {
        enabled: true,
        methods: vec![],
        groups: vec![
            Group {
                id: 1,
                name: "Fixture".into(),
                enabled: true,
                members: vec![
                    member(FIRST, true),
                    member(SECOND, true),
                    member(FOLLOW, false),
                ],
                cidrs: vec!["2001:db8:1::/64".into()],
                expect: vec!["ZZ".into()],
                ..Group::default()
            },
            Group {
                id: 2,
                name: "Independent".into(),
                enabled: true,
                members: vec![member(INDEPENDENT, true)],
                cidrs: vec![],
                expect: vec!["ZZ".into()],
                ..Group::default()
            },
        ],
    };
    let outcome = Arc::new(Mutex::new(ProbeResult::Normal));
    let fixture = outcome.clone();
    let hook: ProbeHook = Arc::new(move |request, _peer| {
        assert_eq!(request.interface, "utun42");
        assert!((1..=2400).contains(&request.timeout_ms));
        assert!(request
            .request
            .starts_with("GET /cdn-cgi/trace HTTP/1.1\r\n"));
        assert_eq!(request.alpn.len(), 2);
        assert!(matches!(
            request.host.as_str(),
            FIRST | SECOND | INDEPENDENT
        ));
        let result = *fixture.lock().unwrap();
        let body = match (request.host.as_str(), result) {
            (SECOND, ProbeResult::ChangedCountry) => "loc=YY\n",
            (SECOND, ProbeResult::MissingCountry) => "irrelevant=value\n",
            (SECOND, ProbeResult::NoAnswer) => return None,
            _ => "loc=ZZ\n",
        };
        Some(format!("HTTP/1.1 200 OK\r\n\r\n{body}").into_bytes())
    });
    let path = directory.0.join("control.sock");
    let controller = Controller::start(&path, config, hook).unwrap();
    let socket = UnixStream::connect(&path).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut socket = BufReader::new(socket);
    let initial = control_read(&mut socket);
    let marker = initial["probe_alpn"].as_str().unwrap();
    let groups: Vec<GateGroup> = serde_json::from_value(initial["groups"].clone()).unwrap();
    let mut gate = Gate::new(
        GateConfig {
            probe_alpn: marker.as_bytes().to_vec(),
            ..GateConfig::default()
        },
        Box::new(ProtectedRoutes::new(&groups)),
    );
    writeln!(socket.get_mut(), "{}", json!({"up":{"ifname":"utun42"}})).unwrap();

    let client = "2001:db8::2".parse().unwrap();
    let site = "2001:db8:1::10".parse().unwrap();
    let sni_site = "2001:db8:2::10".parse().unwrap();
    let now = Instant::now();
    let hold_ipv6 = |gate: &mut Gate, port, destination, hello: &[u8], at| {
        let syn = tcp6(client, port, destination, 443, 1, 0, SYN, &[]);
        assert_eq!(gate.outbound(&syn, at), Step::Forward);
        let data = tcp6(client, port, destination, 443, 2, 77, PA, hello);
        assert_eq!(gate.outbound(&data, at), Step::Consumed);
        data
    };
    let first_hello = hello(Some(FIRST), &[], false, 0);
    let first = hold_ipv6(&mut gate, 58000, sni_site, &first_hello, now);
    assert_eq!(
        decide_held_flow(&mut gate, &mut socket, 1, Some(FIRST), now),
        vec![Out::ToTunnel(first)]
    );

    // The successive checks use the same controller and group configuration.
    // Exceed the documented reuse window without taking down the old flow.
    for (index, result) in [
        ProbeResult::ChangedCountry,
        ProbeResult::MissingCountry,
        ProbeResult::NoAnswer,
    ]
    .into_iter()
    .enumerate()
    {
        *outcome.lock().unwrap() = result;
        let blocked_at = now + Duration::from_secs(2 + index as u64 * 4);
        let port = 58001 + (index as u16 * 2);
        let host = (index == 0).then_some(FOLLOW);
        let destination = if host.is_some() { sni_site } else { site };
        let payload = hello(host, &[], false, 0);
        hold_ipv6(&mut gate, port, destination, &payload, blocked_at);
        let decisions = decide_held_flow(&mut gate, &mut socket, 1, host, blocked_at);
        let [Out::ToHost(reset)] = decisions.as_slice() else {
            panic!("expected only an IPv6 TCP reset: {decisions:?}")
        };
        let reply = parse_ip(reset).unwrap();
        assert_eq!(
            (reply.src, reply.dst),
            (IpAddr::V6(destination), IpAddr::V6(client))
        );
        let L4::Tcp(tcp) = reply.l4 else {
            panic!("expected TCP reset")
        };
        assert_ne!(tcp.flags & RST, 0);
        assert_eq!((tcp.sport, tcp.dport), (443, port));
        verify_checksums(reset);

        let blocked: Value = serde_json::from_str(&controller.status_json()).unwrap();
        assert_eq!(blocked["groups"][0]["state"], "blocked");
        let record = &blocked["records"][0];
        assert!(record["ended"].is_null());
        assert_eq!(record["host"], json!(host));
        let observations = record["observed"].as_array().unwrap();
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0]["host"], FIRST);
        assert_eq!(observations[0]["country"], "ZZ");
        assert_eq!(observations[1]["host"], SECOND);
        if matches!(result, ProbeResult::ChangedCountry) {
            assert_eq!(observations[1]["country"], "YY");
        } else {
            assert!(observations[1]["country"].is_null() && observations[1]["error"].is_string());
        }

        let continuing_data = b"existing";
        let established = tcp6(
            client,
            58000,
            sni_site,
            443,
            2 + (first_hello.len() + index * continuing_data.len()) as u32,
            77,
            PA,
            continuing_data,
        );
        assert_eq!(gate.outbound(&established, blocked_at), Step::Forward);
        let (_, other) = connect_and_send(
            &mut gate,
            port,
            OTHER,
            &hello(Some(INDEPENDENT), &[], false, 0),
            blocked_at,
        );
        assert_eq!(
            decide_held_flow(&mut gate, &mut socket, 2, Some(INDEPENDENT), blocked_at),
            vec![Out::ToTunnel(other)]
        );
        let (free, _) = connect_and_send(
            &mut gate,
            port + 1,
            OTHER,
            &hello(Some("free.example"), &[], false, 0),
            blocked_at,
        );
        assert_eq!(free, Step::Forward);
        for action in gate.drain() {
            let Out::Warm { group, host, destination } = action else { panic!("unexpected action {action:?}") };
            writeln!(socket.get_mut(),"{}",json!({"warm":{"group":group,"host":host,"ip":destination.ip(),"port":destination.port()}})).unwrap();
        }

        *outcome.lock().unwrap() = ProbeResult::Normal;
        let recovered_at = blocked_at + Duration::from_secs(2);
        let unnamed = hello(None, &[], false, 0);
        let recovered = hold_ipv6(&mut gate, port + 1, site, &unnamed, recovered_at);
        assert_eq!(
            decide_held_flow(&mut gate, &mut socket, 1, None, recovered_at),
            vec![Out::ToTunnel(recovered)]
        );
        let status: Value = serde_json::from_str(&controller.status_json()).unwrap();
        assert_eq!(status["groups"][0]["state"], "ok");
        assert_eq!(status["records"].as_array().unwrap().len(), index + 1);
        assert_eq!(status["records"][0]["started"], record["started"]);
        assert!(status["records"][0]["ended"].is_number());
    }
}
