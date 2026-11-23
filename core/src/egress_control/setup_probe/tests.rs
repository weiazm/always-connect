use super::*;
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const HOST: &str = "protected.example.invalid";
const MARKER: &str = "test-marker";

fn answer(query: &[u8], addresses: &[IpAddr]) -> Vec<u8> {
    let mut reply = query.to_vec();
    reply[2..4].copy_from_slice(&[0x81, 0x80]);
    reply[6..8].copy_from_slice(&(addresses.len() as u16).to_be_bytes());
    for address in addresses {
        reply.extend_from_slice(&[0xc0, 12]);
        let (kind, bytes) = match address {
            IpAddr::V4(v4) => (1, v4.octets().to_vec()),
            IpAddr::V6(v6) => (28, v6.octets().to_vec()),
        };
        reply.extend_from_slice(&[0, kind, 0, 1, 0, 0, 0, 60, 0, bytes.len() as u8]);
        reply.extend(bytes);
    }
    reply
}

fn response(country: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nloc={country}\nip=203.0.113.100\n")
        .into_bytes()
}

fn v4(last: u8) -> IpAddr {
    Ipv4Addr::new(192, 0, 2, last).into()
}

fn run(
    method: &str,
    hook: &ProbeHook,
    dns: impl Fn(&[u8], Instant) -> Option<Vec<u8>> + Sync,
    current: impl Fn() -> bool,
) -> Summary {
    let mut summary = Summary::request(HOST, method);
    let method = summary.method(None).unwrap();
    summary.probe(&method, hook, MARKER, "utun99", dns, current)
}

#[test]
fn deduplicates_caps_and_reports_the_confirmed_country_for_each_peer() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    let hook: ProbeHook = Arc::new(move |req, peer| {
        seen.lock().unwrap().push(req.clone());
        *peer = req.connect_ip;
        match req.connect_ip.unwrap() {
            ip if ip == v4(2) => Some(b"HTTP/1.1 404 Not Found\r\n\r\n".to_vec()),
            ip if ip == v4(3) => None,
            ip if ip.is_ipv6() => Some(response("YY")),
            _ => Some(response("ZZ")),
        }
    });
    let dns = |query: &[u8], _| {
        let qtype = query.len() - 3;
        let mut expected = crate::on_demand::dns_query(HOST).unwrap();
        expected[qtype] = query[qtype];
        assert_eq!(query[2..], expected[2..]);
        match query[qtype] {
            1 => Some(answer(
                query,
                &[vec![v4(1)], (1..=9).map(v4).collect()].concat(),
            )),
            28 => Some(answer(query, &["2001:db8::1".parse().unwrap()])),
            _ => panic!("unexpected query type"),
        }
    };
    let summary = serde_json::to_value(run("", &hook, dns, || true)).unwrap();
    assert_eq!(summary["status"], "ok");
    assert_eq!(summary["method"], PRESET_TRACE);
    assert_eq!(summary["resolvedAddressCount"], 10);
    assert_eq!(summary["probedAddressCount"], 8);
    assert_eq!(summary["truncated"], true);
    assert_eq!(summary["coverageIncomplete"], true);
    let rows = summary["results"].as_array().unwrap();
    assert_eq!(rows[0]["country"], "ZZ");
    assert_eq!(rows[1]["country"], "YY");
    assert_eq!(rows[2]["status"], "unsupported");
    assert_eq!(rows[3]["status"], "unavailable");
    assert_eq!(rows[3]["address"], "192.0.2.3");
    assert!(rows.iter().all(|row| row.get("ip").is_none()));

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 8);
    assert_eq!(
        requests
            .iter()
            .map(|req| req.connect_ip.unwrap())
            .collect::<HashSet<_>>()
            .len(),
        8
    );
    for request in requests.iter() {
        assert_eq!(request.host, HOST);
        assert_eq!(request.interface, "utun99");
        assert_eq!(request.alpn, ["http/1.1", MARKER]);
        assert!(request.timeout_ms <= 2400);
        assert_eq!(request.request, format!(
            "GET /cdn-cgi/trace HTTP/1.1\r\nHost: {HOST}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        ));
    }
}

#[test]
fn incomplete_dns_and_missing_or_mismatched_peers_never_supply_country_evidence() {
    let hook: ProbeHook = Arc::new(|req, peer| {
        if req.connect_ip == Some(v4(2)) {
            *peer = Some(v4(1));
        }
        Some(response("ZZ"))
    });
    let dns = |query: &[u8], _| {
        (query[query.len() - 3] == 1)
            .then(|| answer(query, &[v4(1), v4(2), Ipv4Addr::LOCALHOST.into()]))
    };
    let summary = serde_json::to_value(run("", &hook, dns, || true)).unwrap();
    assert_eq!(summary["status"], "unavailable");
    assert_eq!(summary["coverageIncomplete"], true);
    assert_eq!(summary["truncated"], false);
    assert_eq!(summary["resolvedAddressCount"], 3);
    assert_eq!(summary["probedAddressCount"], 2);
    assert!(summary["results"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| { row["status"] == "unavailable" && row.get("country").is_none() }));
}

#[test]
fn rejects_non_site_input_and_methods_with_external_authority() {
    for host in [
        "*.example.invalid",
        "https://example.invalid/",
        "host.invalid\0.other",
        "192.0.2.2",
        "host.invalid..",
    ] {
        let mut summary = Summary::request(host, "");
        assert!(summary.method(None).is_none(), "{host}");
        assert_eq!(
            serde_json::to_value(summary).unwrap()["error"],
            "invalidHost"
        );
    }
    let mut method = super::super::preset_methods().remove(0);
    method.url = "https://other.example.invalid/{host}".into();
    let cfg = EgressConfig {
        methods: vec![method],
        ..Default::default()
    };
    let mut summary = Summary::request(HOST, PRESET_TRACE);
    assert!(summary.method(Some(&cfg)).is_none());
    assert_eq!(
        serde_json::to_value(summary).unwrap()["error"],
        "invalidMethod"
    );
}

#[test]
fn confirms_tunnel_before_http_and_discards_results_after_tunnel_changes() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let hook: ProbeHook = Arc::new(move |req, peer| {
        seen.fetch_add(1, Ordering::Relaxed);
        *peer = req.connect_ip;
        Some(response("ZZ"))
    });
    let dns = |query: &[u8], _| {
        Some(if query[query.len() - 3] == 1 {
            answer(query, &[v4(1)])
        } else {
            answer(query, &[])
        })
    };
    let result = run("", &hook, dns, || false);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(
        serde_json::to_value(result).unwrap()["error"],
        "tunnelUnavailable"
    );

    let result = run("", &hook, dns, || calls.load(Ordering::Relaxed) == 0);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let json = serde_json::to_value(result).unwrap();
    assert_eq!(json["error"], "tunnelUnavailable");
    assert!(json["results"].as_array().unwrap().is_empty());
}

#[test]
fn explicit_method_uses_loopback_dns_and_reports_when_no_peer_has_country_data() {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let resolver = [socket.local_addr().unwrap().to_string()];
    let interface = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };
    let name = std::ffi::CString::new(interface).unwrap();
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    let hook: ProbeHook = Arc::new(|req, peer| {
        assert!(req.request.starts_with("HEAD / HTTP/1.1\r\n"));
        *peer = req.connect_ip;
        Some(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec())
    });
    let result = thread::scope(|scope| {
        scope.spawn(move || {
            for _ in 0..2 {
                let mut buffer = [0; 512];
                let (len, from) = socket.recv_from(&mut buffer).unwrap();
                let query = &buffer[..len];
                let response = if query[len - 3] == 1 {
                    answer(query, &[v4(1)])
                } else {
                    answer(
                        query,
                        &[Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into()],
                    )
                };
                socket.send_to(&response, from).unwrap();
            }
        });
        let dns = |request: &[u8], deadline| {
            crate::dns_forwarder::query_for_setup_probe(
                request, &resolver, interface, index, deadline,
            )
        };
        run(super::super::PRESET_CDN, &hook, dns, || true)
    });
    let json = serde_json::to_value(result).unwrap();
    assert_eq!(json["status"], "unsupported");
    assert_eq!(json["error"], "noCountry");
    assert_eq!(json["coverageIncomplete"], false);
    assert_eq!(json["probedAddressCount"], 2);
}
