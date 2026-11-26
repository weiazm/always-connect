use super::*;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

fn list(lines: &[&str]) -> Vec<String> { lines.iter().map(|s| s.to_string()).collect() }

#[test]
fn table_reads_proxies_and_rules_in_order() {
    let table = Table::parse(&list(&[
        "example.com", "full:direct.example",
        "proxy:0 socks5 127.0.0.1 1080", "via:0:domain:a.example", "via:0:keyword:shared",
        "proxy:1 http proxy.lan 8080 us%20er p%3Ass", "via:1:full:b.example", "via:1:shared.example",
        "via:1:ipcidr:1.2.3.0/24", "vianet:1:203.0.113.0/24",
        "proxy:2 gopher host 1", "via:2:c.example",
        "via:3:d.example",
    ]));
    assert_eq!(table.server(0), Some(&Server { kind: Kind::Socks5, host: "127.0.0.1".into(), port: 1080, auth: None }));
    assert_eq!(table.server(1).unwrap().auth, Some(("us er".into(), "p:ss".into())), "credentials are percent-decoded");
    assert!(!format!("{:?}", table.server(1).unwrap()).contains("p:ss"), "never printed");
    assert_eq!(table.route_name("www.a.example"), Some(0));
    assert_eq!(table.route_name("b.example"), Some(1));
    assert_eq!(table.route_name("x.b.example"), None, "full: is that name only");
    // Both proxies match: the first in the App's order takes it.
    assert_eq!(table.route_name("shared.example"), Some(0));
    // A bad or missing proxy keeps its sites (they are refused, not freed).
    assert_eq!(table.route_name("c.example"), Some(2));
    assert!(table.server(2).is_none());
    assert_eq!(table.route_name("d.example"), Some(3));
    assert!(table.server(3).is_none());
    // The direct list's own lines are not proxy rules.
    assert_eq!(table.route_name("example.com"), None);
    assert_eq!(table.route_name("direct.example"), None);
    // geoip ranges match answers; written networks also take connections by address.
    assert_eq!(table.route_addresses(&[Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(1, 2, 3, 4)]), Some(1));
    assert_eq!(table.route_addresses(&[Ipv4Addr::new(203, 0, 113, 5)]), Some(1));
    assert_eq!(table.route_ip(Ipv4Addr::new(203, 0, 113, 5)), Some(1));
    assert_eq!(table.route_ip(Ipv4Addr::new(1, 2, 3, 4)), None, "geoip ranges are never routed");
    assert_eq!(table.networks(), vec!["203.0.113.0/24".to_owned()]);
    assert!(table.carries_udp());
    assert!(!Table::parse(&list(&["proxy:0 http h 1", "via:0:x.example"])).carries_udp());
}

#[test]
fn an_old_list_has_no_proxies_and_an_old_service_ignores_proxy_lines() {
    assert!(Table::parse(&list(&["example.com", "full:x.example", "ipcidr:10.0.0.0/8"])).is_empty());
    // What a service without this feature does with the new lines: nothing,
    // so a proxied site stays in the VPN there (never direct).
    let direct = SplitRules::new(&list(&["proxy:0 socks5 127.0.0.1 1080 u p", "via:0:domain:a.example", "via:0:a.example",
        "via:0:ipcidr:1.2.3.0/24", "vianet:0:203.0.113.0/24", "direct.example"]));
    assert!(direct.matches("a.example").is_none());
    assert!(direct.matches("www.a.example").is_none());
    assert!(!direct.contains(Ipv4Addr::new(1, 2, 3, 4)) && !direct.contains(Ipv4Addr::new(203, 0, 113, 1)));
    assert!(direct.matches("direct.example").is_some());
}

#[test]
fn server_lines_are_strict() {
    for bad in ["socks5 host", "socks5 host 0", "socks5 host 70000", "socks4 host 1080", "http ho st 80", "http host 80 extra",
                "http h;rm 80", "http host 80 user", "http host 80 user pass extra", "http host 80 %zz pass", "http host 80 u %"] {
        assert!(Server::parse(bad).is_none(), "{bad}");
    }
    assert_eq!(Server::parse("http [::1] 3128").unwrap().host, "::1");
    assert_eq!(Server::parse("http ::1 3128").unwrap().label(), "HTTP [::1]:3128");
}

#[test]
fn each_name_keeps_one_address_in_the_range() {
    let routing = Routing::new(Table::parse(&list(&["proxy:0 socks5 127.0.0.1 1", "via:0:a.example", "via:0:b.example", "via:0:ipcidr:1.2.3.0/24"])));
    let a = routing.answer("WWW.A.example.").unwrap();
    assert!(is_fake(a));
    assert_eq!(routing.answer("www.a.example"), Some(a));
    let b = routing.answer("b.example").unwrap();
    assert_ne!(a, b);
    assert_eq!(routing.name_for(a).as_deref(), Some("www.a.example"));
    assert_eq!(routing.answer("other.example"), None);
    // By address: only when the VPN's answer falls in a proxy's ranges.
    assert_eq!(routing.answer_by_address("other.example", &[Ipv4Addr::new(5, 5, 5, 5)]), None);
    let c = routing.answer_by_address("cdn.example", &[Ipv4Addr::new(1, 2, 3, 9)]).unwrap();
    assert!(is_fake(c) && routing.knows("CDN.example.") && !routing.knows("other.example"));
    assert!(!is_fake(Ipv4Addr::new(198, 18, 0, 1)) && !is_fake(Ipv4Addr::new(198, 19, 127, 255)) && is_fake(Ipv4Addr::new(198, 19, 255, 254)));
}

#[test]
fn the_pool_forgets_the_least_recently_used_names_first() {
    let mut pool = Pool::default();
    let start = Instant::now();
    let first = pool.assign("first.example", &[], start);
    for n in 1..MAX_NAMES { pool.assign(&format!("n{n}.example"), &[], start + Duration::from_millis(n as u64)); }
    pool.assign("first.example", &[], start + Duration::from_secs(100));
    pool.assign("one-more.example", &[], start + Duration::from_secs(101));
    assert!(pool.by_offset.len() <= MAX_NAMES);
    assert_eq!(pool.entry(first, start + Duration::from_secs(102)).map(|e| e.0).as_deref(), Some("first.example"), "recently used survives");
    assert!(!pool.by_name.contains_key("n1.example"), "oldest forgotten");
    // A forgotten name's address is not reused right away.
    let fresh = pool.assign("n1.example", &[], start + Duration::from_secs(103));
    assert!(u32::from(fresh) - FAKE_BASE > MAX_NAMES as u32);
}

// MARK: - Forwarding through test proxies

struct Origin { address: SocketAddr, accepted: Arc<AtomicUsize> }

/// An echo server standing in for every site.
fn origin() -> Origin {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    std::thread::spawn(move || for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        count.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(move || {
            let mut copy = stream.try_clone().unwrap();
            let _ = io::copy(&mut stream, &mut copy);
        });
    });
    Origin { address, accepted }
}

#[derive(Clone, Default)]
struct Behaviour {
    /// Require these credentials (RFC 1929 / Basic).
    password: Option<(&'static str, &'static str)>,
    refuse: bool,
    /// SOCKS5: answer UDP ASSOCIATE with 0.0.0.0 as the relay.
    unspecified_relay: bool,
}

struct TestProxy { port: u16, asked: mpsc::Receiver<String> }

fn splice_test(a: TcpStream, b: TcpStream) {
    let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
    std::thread::spawn(move || { let mut a = a; let mut b = b; let _ = io::copy(&mut a, &mut b); let _ = b.shutdown(Shutdown::Write); });
    std::thread::spawn(move || { let _ = io::copy(&mut b2, &mut a2); let _ = a2.shutdown(Shutdown::Write); });
}

fn read_socks_address(s: &mut TcpStream, atyp: u8) -> String {
    match atyp {
        3 => {
            let mut n = [0u8; 1]; s.read_exact(&mut n).unwrap();
            let mut name = vec![0u8; n[0] as usize + 2]; s.read_exact(&mut name).unwrap();
            let port = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
            format!("{}:{port}", String::from_utf8_lossy(&name[..name.len() - 2]))
        }
        1 => {
            let mut b = [0u8; 6]; s.read_exact(&mut b).unwrap();
            format!("{}:{}", Ipv4Addr::new(b[0], b[1], b[2], b[3]), u16::from_be_bytes([b[4], b[5]]))
        }
        _ => panic!("unexpected address type"),
    }
}

/// A minimal SOCKS5 server: CONNECT (to the origin whatever was asked)
/// and UDP ASSOCIATE (echoes each datagram back as "echo:<payload>").
fn socks_proxy(origin: SocketAddr, behaviour: Behaviour) -> TestProxy {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, asked) = mpsc::channel();
    std::thread::spawn(move || for stream in listener.incoming() {
        let Ok(mut s) = stream else { continue };
        let (tx, behaviour) = (tx.clone(), behaviour.clone());
        std::thread::spawn(move || {
            let mut head = [0u8; 2];
            s.read_exact(&mut head).unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            s.read_exact(&mut methods).unwrap();
            match behaviour.password {
                Some((user, password)) => {
                    if !methods.contains(&2) { s.write_all(&[5, 0xff]).unwrap(); return; }
                    s.write_all(&[5, 2]).unwrap();
                    let mut v = [0u8; 2]; s.read_exact(&mut v).unwrap();
                    let mut u = vec![0u8; v[1] as usize]; s.read_exact(&mut u).unwrap();
                    let mut pl = [0u8; 1]; s.read_exact(&mut pl).unwrap();
                    let mut p = vec![0u8; pl[0] as usize]; s.read_exact(&mut p).unwrap();
                    let ok = u == user.as_bytes() && p == password.as_bytes();
                    s.write_all(&[1, if ok { 0 } else { 1 }]).unwrap();
                    if !ok { return; }
                }
                None => s.write_all(&[5, 0]).unwrap(),
            }
            let mut request = [0u8; 4];
            s.read_exact(&mut request).unwrap();
            let address = read_socks_address(&mut s, request[3]);
            if request[1] == 3 {
                let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
                let relay_port = relay.local_addr().unwrap().port();
                let shown = if behaviour.unspecified_relay { [0, 0, 0, 0] } else { [127, 0, 0, 1] };
                let mut reply = vec![5, 0, 0, 1];
                reply.extend_from_slice(&shown);
                reply.extend_from_slice(&relay_port.to_be_bytes());
                s.write_all(&reply).unwrap();
                let tx = tx.clone();
                std::thread::spawn(move || {
                    let mut buffer = [0u8; 2048];
                    while let Ok((n, from)) = relay.recv_from(&mut buffer) {
                        let packet = &buffer[..n];
                        let header = match packet[3] { 1 => 10, 3 => 7 + packet[4] as usize, _ => continue };
                        let target = if packet[3] == 3 {
                            format!("{}:{}", String::from_utf8_lossy(&packet[5..5 + packet[4] as usize]), u16::from_be_bytes([packet[header - 2], packet[header - 1]]))
                        } else {
                            format!("{}:{}", Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]), u16::from_be_bytes([packet[8], packet[9]]))
                        };
                        let _ = tx.send(format!("udp {target}"));
                        let mut answer = packet[..header].to_vec();
                        answer.extend_from_slice(b"echo:");
                        answer.extend_from_slice(&packet[header..]);
                        let _ = relay.send_to(&answer, from);
                    }
                });
                // The association lives as long as the control connection.
                let mut rest = Vec::new();
                let _ = s.read_to_end(&mut rest);
                return;
            }
            tx.send(address).unwrap();
            if behaviour.refuse { s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap(); return; }
            s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
            splice_test(s, TcpStream::connect(origin).unwrap());
        });
    });
    TestProxy { port, asked }
}

/// A minimal HTTP CONNECT proxy. Sends "early:" right after its header
/// (bytes the listener must pass on).
fn http_proxy(origin: SocketAddr, behaviour: Behaviour) -> TestProxy {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, asked) = mpsc::channel();
    std::thread::spawn(move || for stream in listener.incoming() {
        let Ok(mut s) = stream else { continue };
        let (tx, behaviour) = (tx.clone(), behaviour.clone());
        std::thread::spawn(move || {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") { s.read_exact(&mut byte).unwrap(); head.push(byte[0]); }
            let head = String::from_utf8(head).unwrap();
            let line = head.lines().next().unwrap().to_owned();
            tx.send(line.split_whitespace().nth(1).unwrap().to_owned()).unwrap();
            assert!(line.starts_with("CONNECT ") && head.contains("\r\nHost: "));
            if let Some((user, password)) = behaviour.password {
                let wanted = format!("Proxy-Authorization: Basic {}", protocol_base64(&format!("{user}:{password}")));
                if !head.lines().any(|l| l == wanted) {
                    s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").unwrap();
                    return;
                }
            }
            if behaviour.refuse { s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").unwrap(); return; }
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nearly:").unwrap();
            splice_test(s, TcpStream::connect(origin).unwrap());
        });
    });
    TestProxy { port, asked }
}

/// Reference encoder for the test proxy (independent of the client's).
fn protocol_base64(text: &str) -> String {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bits: String = text.bytes().map(|b| format!("{b:08b}")).collect();
    let mut out: String = bits.as_bytes().chunks(6).map(|c| {
        let mut s = String::from_utf8(c.to_vec()).unwrap();
        while s.len() < 6 { s.push('0'); }
        table[usize::from_str_radix(&s, 2).unwrap()] as char
    }).collect();
    while out.len() % 4 != 0 { out.push('='); }
    out
}

/// The listener with a stand-in for pf: each test client registers the
/// address it "meant" under its own local port before sending.
struct Rig { listener: Listener, routing: Arc<Routing>, meant: Arc<Mutex<HashMap<u16, SocketAddrV4>>> }

fn rig(lines: &[String]) -> Rig {
    let routing = Routing::new(Table::parse(lines));
    // The stand-in proxies live in this process, like the test's apps.
    routing.same_process_proxies.store(true, Ordering::Relaxed);
    let meant: Arc<Mutex<HashMap<u16, SocketAddrV4>>> = Arc::default();
    let lookup = meant.clone();
    let original: OriginalDestination = Arc::new(move |_proto, peer: SocketAddrV4, _local| lookup.lock().unwrap().get(&peer.port()).copied());
    Rig { listener: Listener::start(routing.clone(), original).unwrap(), routing, meant }
}

impl Rig {
    fn open(&self, name: &str, port: u16) -> TcpStream {
        let ip = self.routing.answer(name).expect("a proxied name");
        self.open_address(SocketAddrV4::new(ip, port))
    }

    fn open_address(&self, meant: SocketAddrV4) -> TcpStream {
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into()).unwrap();
        let local = socket.local_addr().unwrap().as_socket().unwrap().port();
        self.meant.lock().unwrap().insert(local, meant);
        socket.connect(&SocketAddr::from((Ipv4Addr::LOCALHOST, self.listener.port())).into()).unwrap();
        let stream: TcpStream = socket.into();
        stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        stream
    }

    fn udp(&self, meant: SocketAddrV4) -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        self.meant.lock().unwrap().insert(socket.local_addr().unwrap().port(), meant);
        socket.connect(("127.0.0.1", self.listener.udp_port())).unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        socket
    }
}

fn round_trip(stream: &mut TcpStream, expect_prefix: &str) {
    stream.write_all(b"ping through the proxy").unwrap();
    let want = format!("{expect_prefix}ping through the proxy");
    let mut got = vec![0u8; want.len()];
    stream.read_exact(&mut got).unwrap();
    assert_eq!(String::from_utf8(got).unwrap(), want);
}

/// The app sees the connection end (reset or closed) without data.
fn refused(mut stream: TcpStream) {
    let _ = stream.write_all(b"hello");
    let mut buf = [0u8; 16];
    match stream.read(&mut buf) {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("expected the connection to be refused, got {n} bytes"),
    }
}

/// Sends until an answer comes (the first datagrams are dropped while the
/// association is set up, as an app's retransmissions would cover).
fn udp_exchange(socket: &UdpSocket, payload: &[u8]) -> Option<Vec<u8>> { udp_tries(socket, payload, 30) }

fn udp_tries(socket: &UdpSocket, payload: &[u8], tries: usize) -> Option<Vec<u8>> {
    let mut buf = [0u8; 2048];
    for _ in 0..tries {
        socket.send(payload).unwrap();
        if let Ok(n) = socket.recv(&mut buf) { return Some(buf[..n].to_vec()); }
    }
    None
}

#[test]
fn socks5_carries_the_name_and_both_directions() {
    let site = origin();
    let proxy = socks_proxy(site.address, Behaviour::default());
    let r = rig(&list(&[&format!("proxy:0 socks5 127.0.0.1 {}", proxy.port), "via:0:domain:site.example"]));
    let mut app = r.open("www.site.example", 443);
    round_trip(&mut app, "");
    assert_eq!(proxy.asked.recv_timeout(Duration::from_secs(5)).unwrap(), "www.site.example:443", "the proxy resolves the name");
    assert_eq!(r.routing.connections(), 1);
    // Half-close: the app finishing its side still gets the rest back.
    app.write_all(b"tail").unwrap();
    app.shutdown(Shutdown::Write).unwrap();
    let mut rest = Vec::new();
    app.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"tail");
}

#[test]
fn passwords_reach_socks5_and_http_proxies() {
    let site = origin();
    let socks = socks_proxy(site.address, Behaviour { password: Some(("alice", "s3cret:pw")), ..Default::default() });
    let http = http_proxy(site.address, Behaviour { password: Some(("alice", "s3cret:pw")), ..Default::default() });
    let r = rig(&list(&[
        &format!("proxy:0 socks5 127.0.0.1 {} alice s3cret%3Apw", socks.port), "via:0:full:s.example",
        &format!("proxy:1 http 127.0.0.1 {} alice s3cret%3Apw", http.port), "via:1:full:h.example",
    ]));
    round_trip(&mut r.open("s.example", 443), "");
    round_trip(&mut r.open("h.example", 443), "early:");
    // Wrong or missing passwords are refusals with their reason.
    for (line, expect) in [
        (format!("proxy:0 socks5 127.0.0.1 {} alice wrong", socks.port), "拒绝了用户名或密码"),
        (format!("proxy:0 socks5 127.0.0.1 {}", socks.port), "要求用户名密码"),
        (format!("proxy:0 http 127.0.0.1 {} alice wrong", http.port), "拒绝了用户名或密码"),
        (format!("proxy:0 http 127.0.0.1 {}", http.port), "要求用户名密码"),
    ] {
        r.routing.set_table(Table::parse(&list(&[&line, "via:0:full:x.example"])));
        refused(r.open("x.example", 443));
        let notice = r.routing.recent_notice().unwrap();
        assert!(notice.contains(expect), "{line}: {notice}");
    }
    assert_eq!(site.accepted.load(Ordering::SeqCst), 2);
}

#[test]
fn http_connect_carries_the_name_and_early_bytes() {
    let site = origin();
    let proxy = http_proxy(site.address, Behaviour::default());
    let r = rig(&list(&[&format!("proxy:0 http localhost {}", proxy.port), "via:0:full:api.site.example"]));
    let mut app = r.open("api.site.example", 8443);
    round_trip(&mut app, "early:");
    assert_eq!(proxy.asked.recv_timeout(Duration::from_secs(5)).unwrap(), "api.site.example:8443");
}

#[test]
fn sites_matched_by_address_and_networks_go_through_the_proxy() {
    let site = origin();
    let proxy = socks_proxy(site.address, Behaviour::default());
    let r = rig(&list(&[&format!("proxy:0 socks5 127.0.0.1 {}", proxy.port), "via:0:ipcidr:1.2.3.0/24", "vianet:0:203.0.113.0/24"]));
    // geoip-style: the name's answer fell in the range; the proxy still gets the name.
    let ip = r.routing.answer_by_address("cdn.example", &[Ipv4Addr::new(1, 2, 3, 4)]).unwrap();
    round_trip(&mut r.open_address(SocketAddrV4::new(ip, 443)), "");
    assert_eq!(proxy.asked.recv_timeout(Duration::from_secs(5)).unwrap(), "cdn.example:443");
    // A connection straight to an address in a written network.
    round_trip(&mut r.open_address(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 8), 22)), "");
    assert_eq!(proxy.asked.recv_timeout(Duration::from_secs(5)).unwrap(), "203.0.113.8:22");
    // An address outside every network is refused, never passed on.
    refused(r.open_address(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 22)));
    assert!(r.routing.recent_notice().unwrap().contains("不在代理规则里"));
}

#[test]
fn udp_goes_through_socks5_by_name_and_address() {
    let site = origin();
    for unspecified_relay in [false, true] {
        let proxy = socks_proxy(site.address, Behaviour { unspecified_relay, password: Some(("u", "p")), ..Default::default() });
        let r = rig(&list(&[&format!("proxy:0 socks5 127.0.0.1 {} u p", proxy.port), "via:0:quic.example", "vianet:0:203.0.113.0/24"]));
        let ip = r.routing.answer("quic.example").unwrap();
        let app = r.udp(SocketAddrV4::new(ip, 443));
        assert_eq!(udp_exchange(&app, b"hello").as_deref(), Some(&b"echo:hello"[..]), "relay 0.0.0.0 = the proxy's own address: {unspecified_relay}");
        assert_eq!(proxy.asked.recv_timeout(Duration::from_secs(5)).unwrap(), "udp quic.example:443");
        let by_ip = r.udp(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 53));
        assert_eq!(udp_exchange(&by_ip, b"q").as_deref(), Some(&b"echo:q"[..]));
        while let Ok(seen) = proxy.asked.try_recv() { assert!(seen.starts_with("udp quic.example") || seen == "udp 203.0.113.9:53", "{seen}"); }
    }
}

#[test]
fn udp_is_never_sent_another_way() {
    let site = origin();
    let http = http_proxy(site.address, Behaviour::default());
    let socks = socks_proxy(site.address, Behaviour { password: Some(("u", "p")), ..Default::default() });
    let r = rig(&list(&[
        &format!("proxy:0 http 127.0.0.1 {}", http.port), "via:0:h.example",
        &format!("proxy:1 socks5 127.0.0.1 {} u wrong", socks.port), "via:1:s.example",
    ]));
    // HTTP proxies carry TCP only: datagrams are dropped (the app falls back).
    let h = r.udp(SocketAddrV4::new(r.routing.answer("h.example").unwrap(), 443));
    assert_eq!(udp_tries(&h, b"x", 5), None);
    // A refused association drops the flow's datagrams and says why.
    let s = r.udp(SocketAddrV4::new(r.routing.answer("s.example").unwrap(), 443));
    assert_eq!(udp_tries(&s, b"x", 5), None);
    assert!(r.routing.recent_notice().unwrap().contains("拒绝了用户名或密码"));
    assert!(http.asked.try_recv().is_err());
}

#[test]
fn rules_pick_the_first_matching_proxy() {
    let site = origin();
    let socks = socks_proxy(site.address, Behaviour::default());
    let http = http_proxy(site.address, Behaviour::default());
    let r = rig(&list(&[
        &format!("proxy:0 http 127.0.0.1 {}", http.port), "via:0:full:only-http.example", "via:0:keyword:both",
        &format!("proxy:1 socks5 127.0.0.1 {}", socks.port), "via:1:both.example", "via:1:only-socks.example",
    ]));
    round_trip(&mut r.open("both.example", 443), "early:");
    assert_eq!(http.asked.recv_timeout(Duration::from_secs(5)).unwrap(), "both.example:443");
    round_trip(&mut r.open("only-socks.example", 443), "");
    assert_eq!(socks.asked.recv_timeout(Duration::from_secs(5)).unwrap(), "only-socks.example:443");
    assert!(http.asked.try_recv().is_err() && socks.asked.try_recv().is_err());
}

#[test]
fn a_proxy_that_is_down_refuses_and_never_goes_direct() {
    let site = origin();
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = unused.local_addr().unwrap().port();
    drop(unused);
    let r = rig(&list(&[&format!("proxy:0 socks5 127.0.0.1 {port}"), "via:0:site.example"]));
    refused(r.open("site.example", 80));
    assert_eq!(site.accepted.load(Ordering::SeqCst), 0);
    assert!(r.routing.recent_notice().unwrap().contains("拒绝连接"));
}

#[test]
fn proxies_that_say_no_are_refusals() {
    let site = origin();
    let refuse = Behaviour { refuse: true, ..Default::default() };
    for (proxy, kind, expect) in [
        (socks_proxy(site.address, refuse.clone()), "socks5", "拒绝"),
        (http_proxy(site.address, refuse.clone()), "http", "403"),
    ] {
        let r = rig(&list(&[&format!("proxy:0 {kind} 127.0.0.1 {}", proxy.port), "via:0:site.example"]));
        refused(r.open("site.example", 443));
        let notice = r.routing.recent_notice().unwrap();
        assert!(notice.contains(expect), "{kind}: {notice}");
    }
    assert_eq!(site.accepted.load(Ordering::SeqCst), 0);
}

#[test]
fn changed_rules_missing_proxies_and_unknown_addresses_are_refused() {
    let site = origin();
    let proxy = socks_proxy(site.address, Behaviour::default());
    let server = format!("proxy:0 socks5 127.0.0.1 {}", proxy.port);
    let r = rig(&list(&[&server, "via:0:a.example", "via:1:b.example"]));
    // The rule pointed at a proxy that is not declared.
    refused(r.open("b.example", 443));
    assert!(r.routing.recent_notice().unwrap().contains("代理不存在"));
    // The answer was given, then the rule went away.
    let ip = r.routing.answer("a.example").unwrap();
    r.routing.set_table(Table::parse(&list(&[&server, "via:0:other.example"])));
    refused(r.open_address(SocketAddrV4::new(ip, 443)));
    assert!(r.routing.recent_notice().unwrap().contains("规则已改"));
    // An address we never handed out.
    refused(r.open_address(SocketAddrV4::new(Ipv4Addr::new(198, 19, 200, 1), 443)));
    // Not a redirected connection at all.
    let stray = TcpStream::connect(("127.0.0.1", r.listener.port())).unwrap();
    stray.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    refused(stray);
    assert_eq!(site.accepted.load(Ordering::SeqCst), 0);
    assert!(proxy.asked.try_recv().is_err());
}

#[test]
fn a_proxy_address_inside_the_proxied_range_is_refused() {
    let r = rig(&list(&["proxy:0 socks5 198.19.128.9 1080", "via:0:site.example"]));
    refused(r.open("site.example", 443));
    assert!(r.routing.recent_notice().unwrap().contains("命中了代理规则"));
}

#[test]
fn stopping_ends_open_connections() {
    let site = origin();
    let proxy = socks_proxy(site.address, Behaviour::default());
    let mut r = rig(&list(&[&format!("proxy:0 socks5 127.0.0.1 {}", proxy.port), "via:0:site.example"]));
    let mut app = r.open("site.example", 443);
    round_trip(&mut app, "");
    r.listener.stop();
    let mut buf = [0u8; 8];
    assert!(matches!(app.read(&mut buf), Ok(0) | Err(_)));
}

/// Interoperability with a reference SOCKS5 server (CI runs Dante with
/// username/password, `scripts/socks5-interop-test.sh`):
/// AC_SOCKS5_INTEROP=host:port, AC_SOCKS5_INTEROP_AUTH=user:password.
#[test]
#[ignore]
fn interop_with_a_reference_socks5_server() {
    let address = std::env::var("AC_SOCKS5_INTEROP").expect("AC_SOCKS5_INTEROP=host:port");
    let (host, port) = address.rsplit_once(':').unwrap();
    let (user, password) = std::env::var("AC_SOCKS5_INTEROP_AUTH").expect("AC_SOCKS5_INTEROP_AUTH=user:password")
        .split_once(':').map(|(u, p)| (u.to_owned(), p.to_owned())).unwrap();
    let server = |auth: Option<(String, String)>| Server { kind: Kind::Socks5, host: host.into(), port: port.parse().unwrap(), auth };
    let site = origin();
    let site_port = site.address.port();
    // TCP by address and by name (the server resolves "127.0.0.1" itself).
    for target in [Target::Ip(Ipv4Addr::LOCALHOST), Target::Name("127.0.0.1".into())] {
        let (mut stream, early) = open_through(&server(Some((user.clone(), password.clone()))), &target, site_port)
            .unwrap_or_else(|e| panic!("CONNECT {target:?}: {e}"));
        assert!(early.is_empty());
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        round_trip(&mut stream, "");
    }
    // The server requires the password: without it, or with a wrong one, a
    // clear refusal (AC_SOCKS5_INTEROP_LAX=1: a server that lets clients
    // without a password in, as some do; only the wrong password is checked).
    let lax = std::env::var_os("AC_SOCKS5_INTEROP_LAX").is_some();
    if !lax {
    let missing = open_through(&server(None), &Target::Ip(Ipv4Addr::LOCALHOST), site_port).unwrap_err();
    assert!(missing.contains("要求用户名密码") || missing.contains("认证方式"), "{missing}");
    }
    let wrong = open_through(&server(Some((user.clone(), "wrong".into()))), &Target::Ip(Ipv4Addr::LOCALHOST), site_port).unwrap_err();
    assert!(wrong.contains("拒绝了用户名或密码"), "{wrong}");
    // UDP ASSOCIATE through the server's relay to a local UDP echo.
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = echo.recv_from(&mut buf) { let _ = echo.send_to(&buf[..n], from); }
    });
    let (_control, relay) = udp_associate(&server(Some((user, password)))).expect("UDP ASSOCIATE");
    relay.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    for target in [Target::Ip(Ipv4Addr::LOCALHOST), Target::Name("127.0.0.1".into())] {
        let mut answered = None;
        for _ in 0..10 {
            relay.send(&udp_wrap(&target, echo_port, b"datagram").unwrap()).unwrap();
            let mut buf = [0u8; 2048];
            if let Ok(n) = relay.recv(&mut buf) { answered = udp_unwrap(&buf[..n]).map(<[u8]>::to_vec); break; }
        }
        assert_eq!(answered.as_deref(), Some(&b"datagram"[..]), "UDP via {target:?}");
    }
}

/// A proxy running on this Mac (another process) resolves the proxied
/// name through us and connects to our address for its own upstream:
/// that connection goes to the real address, never back into the proxy.
#[cfg(target_os = "macos")]
#[test]
fn a_local_proxys_own_connection_goes_to_the_real_address() {
    use std::io::BufRead;
    let site = origin();
    let r = rig(&list(&[]));
    r.routing.same_process_proxies.store(false, Ordering::Relaxed);
    let script = "import socket,sys\n\
l=socket.socket(); l.bind(('127.0.0.1',0)); l.listen(1)\n\
c=socket.socket(); c.bind(('127.0.0.1',0))\n\
print(l.getsockname()[1], c.getsockname()[1], flush=True)\n\
sys.stdin.readline()\n\
c.connect(('127.0.0.1', int(sys.argv[1]))); c.sendall(b'ping')\n\
print(c.recv(16).decode() or 'closed', flush=True)\n";
    let mut child = std::process::Command::new("/usr/bin/python3").args(["-c", script, &r.listener.port().to_string()])
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
    let mut out = io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    out.read_line(&mut line).unwrap();
    let ports: Vec<u16> = line.split_whitespace().map(|p| p.parse().unwrap()).collect();
    // The child's listening port is the configured proxy.
    r.routing.set_table(Table::parse(&list(&[&format!("proxy:0 socks5 127.0.0.1 {}", ports[0]), "via:0:site.example"])));
    let resolved = Arc::new(AtomicUsize::new(0));
    let count = resolved.clone();
    r.routing.set_resolver(Some(Arc::new(move |name: &str| {
        assert_eq!(name, "site.example");
        count.fetch_add(1, Ordering::SeqCst);
        vec![Ipv4Addr::LOCALHOST]
    })));
    let ip = r.routing.answer("site.example").unwrap();
    r.meant.lock().unwrap().insert(ports[1], SocketAddrV4::new(ip, site.address.port()));
    child.stdin.as_mut().unwrap().write_all(b"go\n").unwrap();
    line.clear();
    out.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ping", "echoed by the real site");
    assert_eq!(site.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(resolved.load(Ordering::SeqCst), 1);
    let _ = child.wait();
    // This process is not the proxy: its connection still goes to the proxy
    // (which does not speak SOCKS here, so it is refused, never passed through).
    refused(r.open("site.example", site.address.port()));
    assert_eq!(site.accepted.load(Ordering::SeqCst), 1);
}

// MARK: - Checks and health (§69.8)

#[test]
fn a_check_tells_reach_password_and_site_apart() {
    let site = origin();
    let socks = socks_proxy(site.address, Behaviour { password: Some(("alice", "pw")), ..Default::default() });
    let http = http_proxy(site.address, Behaviour { password: Some(("alice", "pw")), ..Default::default() });
    let refusing_socks = socks_proxy(site.address, Behaviour { refuse: true, ..Default::default() });
    let refusing_http = http_proxy(site.address, Behaviour { refuse: true, ..Default::default() });
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let down = unused.local_addr().unwrap().port();
    drop(unused);
    let check = |line: String, site: Option<&str>| probe(&Server::parse(&line).unwrap(), site);
    for (line, site, level, expect) in [
        (format!("socks5 127.0.0.1 {} alice pw", socks.port), Some("s.example"), Level::Ok, "经代理打开 s.example 正常"),
        (format!("socks5 127.0.0.1 {} alice pw", socks.port), None, Level::Ok, "用户名密码正确"),
        (format!("socks5 127.0.0.1 {} alice wrong", socks.port), Some("s.example"), Level::Fail, "拒绝了用户名或密码"),
        (format!("socks5 127.0.0.1 {}", socks.port), Some("s.example"), Level::Fail, "要求用户名密码"),
        (format!("socks5 127.0.0.1 {}", refusing_socks.port), Some("s.example"), Level::Warn, "打不开 s.example"),
        (format!("socks5 127.0.0.1 {down}"), Some("s.example"), Level::Fail, "拒绝连接"),
        (format!("http 127.0.0.1 {} alice pw", http.port), Some("h.example"), Level::Ok, "经代理打开 h.example 正常"),
        (format!("http 127.0.0.1 {} alice wrong", http.port), Some("h.example"), Level::Fail, "拒绝了用户名或密码"),
        (format!("http 127.0.0.1 {}", refusing_http.port), Some("h.example"), Level::Warn, "403"),
        (format!("http 127.0.0.1 {}", http.port), None, Level::Ok, "密码要等用时才核对"),
        // Something that is not a proxy at all (the echo server).
        (format!("socks5 127.0.0.1 {}", site.address.port()), Some("s.example"), Level::Fail, "不支持的认证方式"),
        (format!("http 127.0.0.1 {}", site.address.port()), Some("h.example"), Level::Fail, "不是 HTTP 代理"),
    ] {
        let result = check(line.clone(), site);
        assert_eq!(result.level, level, "{line}: {}", result.text);
        assert!(result.text.contains(expect), "{line}: {}", result.text);
    }
}

#[test]
fn the_site_to_check_is_the_first_plain_name() {
    assert_eq!(site_from_rules(&["geosite:github", "geoip:cn", "keyword:abc", "203.0.113.0/24", "full:Api.Example.org", "example.com"]),
               Some("api.example.org".into()));
    assert_eq!(site_from_rules(&["example.com"]), Some("example.com".into()));
    assert_eq!(site_from_rules(&["geosite:github", "10.0.0.1", "regexp:.*"]), None);
    assert_eq!(site_from_rules::<&str>(&[]), None);
}

#[test]
fn forwarded_bytes_are_counted_by_the_road_to_the_proxy() {
    // §69.17: the panel's 代理 speed. A proxy on this Mac is the local road.
    let site = origin();
    let proxy = socks_proxy(site.address, Behaviour::default());
    let r = rig(&list(&[&format!("proxy:0 socks5 127.0.0.1 {}", proxy.port), "via:0:full:count.example"]));
    let mut stream = r.open("count.example", 443);
    round_trip(&mut stream, "");
    let deadline = Instant::now() + Duration::from_secs(5);
    let sent = "ping through the proxy".len() as u64;
    loop {
        let traffic = r.routing.traffic_json();
        if traffic["local"][0].as_u64() == Some(sent) && traffic["local"][1].as_u64() == Some(sent) {
            assert_eq!(traffic["direct"], serde_json::json!([0, 0]));
            assert_eq!(traffic["vpn"], serde_json::json!([0, 0]));
            break;
        }
        assert!(Instant::now() < deadline, "{traffic}");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(Leg::of("127.0.0.1".parse().unwrap()), Leg::Local);
}

#[test]
fn each_proxy_reports_its_last_success_and_failure() {
    let site = origin();
    let good = socks_proxy(site.address, Behaviour::default());
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let down = unused.local_addr().unwrap().port();
    drop(unused);
    let r = rig(&list(&[
        &format!("proxy:0 socks5 127.0.0.1 {}", good.port), "via:0:full:good.example",
        &format!("proxy:1 socks5 127.0.0.1 {down}"), "via:1:full:down.example",
    ]));
    assert_eq!(r.routing.health_json(), serde_json::json!([]));
    round_trip(&mut r.open("good.example", 443), "");
    refused(r.open("down.example", 443));
    let health = r.routing.health_json();
    let rows = health.as_array().unwrap();
    assert_eq!(rows.len(), 2, "{health}");
    assert_eq!(rows[0]["proxy"], 0);
    assert!(rows[0]["okAgo"].is_u64() && rows[0]["failedAgo"].is_null(), "{health}");
    assert_eq!(rows[1]["proxy"], 1);
    assert!(rows[1]["okAgo"].is_null() && rows[1]["failedAgo"].is_u64(), "{health}");
    assert!(rows[1]["reason"].as_str().unwrap().contains("拒绝连接"), "{health}");
}
