use super::*;
use std::net::TcpListener;
use std::sync::mpsc;

fn list(lines: &[&str]) -> Vec<String> { lines.iter().map(|s| s.to_string()).collect() }

#[test]
fn table_reads_proxies_and_rules_in_order() {
    let table = Table::parse(&list(&[
        "example.com", "full:direct.example",
        "proxy:0 socks5 127.0.0.1 1080", "via:0:domain:a.example", "via:0:keyword:shared",
        "proxy:1 http proxy.lan 8080", "via:1:full:b.example", "via:1:shared.example", "via:1:ipcidr:1.2.3.0/24",
        "proxy:2 gopher host 1", "via:2:c.example",
        "via:3:d.example",
    ]));
    assert_eq!(table.server(0), Some(&Server { kind: Kind::Socks5, host: "127.0.0.1".into(), port: 1080 }));
    assert_eq!(table.server(1).map(|s| s.kind), Some(Kind::Http));
    assert_eq!(table.route("www.a.example"), Some(0));
    assert_eq!(table.route("b.example"), Some(1));
    assert_eq!(table.route("x.b.example"), None, "full: is that name only");
    // Both proxies match: the first in the App's order takes it.
    assert_eq!(table.route("shared.example"), Some(0));
    // A bad or missing proxy keeps its names (they are refused, not freed).
    assert_eq!(table.route("c.example"), Some(2));
    assert!(table.server(2).is_none());
    assert_eq!(table.route("d.example"), Some(3));
    assert!(table.server(3).is_none());
    // The direct list's own lines are not proxy rules.
    assert_eq!(table.route("example.com"), None);
    assert_eq!(table.route("direct.example"), None);
}

#[test]
fn an_old_list_has_no_proxies_and_an_old_service_ignores_proxy_lines() {
    assert!(Table::parse(&list(&["example.com", "full:x.example", "ipcidr:10.0.0.0/8"])).is_empty());
    // What a service without this feature does with the new lines: nothing,
    // so a proxied name stays in the VPN there (never direct).
    let direct = SplitRules::new(&list(&["proxy:0 socks5 127.0.0.1 1080", "via:0:domain:a.example", "via:0:a.example", "direct.example"]));
    assert!(direct.matches("a.example").is_none());
    assert!(direct.matches("www.a.example").is_none());
    assert!(direct.matches("direct.example").is_some());
}

#[test]
fn server_lines_are_strict() {
    for bad in ["socks5 host", "socks5 host 0", "socks5 host 70000", "socks4 host 1080", "http ho st 80", "http host 80 extra", "http h;rm 80"] {
        assert!(Server::parse(bad).is_none(), "{bad}");
    }
    assert_eq!(Server::parse("http [::1] 3128").unwrap().host, "::1");
}

#[test]
fn each_name_keeps_one_address_in_the_range() {
    let routing = Routing::new(Table::parse(&list(&["proxy:0 socks5 127.0.0.1 1", "via:0:a.example", "via:0:b.example"])));
    let a = routing.answer("WWW.A.example.").unwrap();
    assert!(is_fake(a));
    assert_eq!(routing.answer("www.a.example"), Some(a));
    let b = routing.answer("b.example").unwrap();
    assert_ne!(a, b);
    assert_eq!(routing.name_for(a).as_deref(), Some("www.a.example"));
    assert_eq!(routing.answer("other.example"), None);
    assert!(!is_fake(Ipv4Addr::new(198, 18, 0, 1)) && !is_fake(Ipv4Addr::new(198, 19, 127, 255)) && is_fake(Ipv4Addr::new(198, 19, 255, 254)));
}

#[test]
fn the_pool_forgets_the_least_recently_used_names_first() {
    let mut pool = Pool::default();
    let start = Instant::now();
    let first = pool.assign("first.example", start);
    for n in 1..MAX_NAMES { pool.assign(&format!("n{n}.example"), start + Duration::from_millis(n as u64)); }
    pool.assign("first.example", start + Duration::from_secs(100));
    pool.assign("one-more.example", start + Duration::from_secs(101));
    assert!(pool.by_offset.len() <= MAX_NAMES);
    assert_eq!(pool.name(first, start + Duration::from_secs(102)).as_deref(), Some("first.example"), "recently used survives");
    assert!(pool.by_name.get("n1.example").is_none(), "oldest forgotten");
    // A forgotten name's address is not reused right away.
    let fresh = pool.assign("n1.example", start + Duration::from_secs(103));
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

#[derive(Clone, Copy, PartialEq)]
enum Behaviour { Works, WantsPassword, Refuses }

struct TestProxy { port: u16, asked: mpsc::Receiver<String> }

fn splice_test(a: TcpStream, b: TcpStream) {
    let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
    std::thread::spawn(move || { let mut a = a; let mut b = b; let _ = io::copy(&mut a, &mut b); let _ = b.shutdown(Shutdown::Write); });
    std::thread::spawn(move || { let _ = io::copy(&mut b2, &mut a2); let _ = a2.shutdown(Shutdown::Write); });
}

/// A minimal SOCKS5 server: records the requested "name:port", then
/// connects to the origin whatever was asked.
fn socks_proxy(origin: SocketAddr, behaviour: Behaviour) -> TestProxy {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, asked) = mpsc::channel();
    std::thread::spawn(move || for stream in listener.incoming() {
        let Ok(mut s) = stream else { continue };
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut head = [0u8; 2];
            s.read_exact(&mut head).unwrap();
            let mut methods = vec![0u8; head[1] as usize];
            s.read_exact(&mut methods).unwrap();
            if behaviour == Behaviour::WantsPassword { s.write_all(&[5, 0xff]).unwrap(); return; }
            s.write_all(&[5, 0]).unwrap();
            let mut request = [0u8; 5];
            s.read_exact(&mut request).unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 3], "CONNECT by name");
            let mut name = vec![0u8; request[4] as usize + 2];
            s.read_exact(&mut name).unwrap();
            let port = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
            tx.send(format!("{}:{port}", String::from_utf8_lossy(&name[..name.len() - 2]))).unwrap();
            if behaviour == Behaviour::Refuses { s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap(); return; }
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
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") { s.read_exact(&mut byte).unwrap(); head.push(byte[0]); }
            let head = String::from_utf8(head).unwrap();
            let line = head.lines().next().unwrap().to_owned();
            tx.send(line.split_whitespace().nth(1).unwrap().to_owned()).unwrap();
            assert!(line.starts_with("CONNECT ") && head.contains("\r\nHost: "));
            match behaviour {
                Behaviour::WantsPassword => { s.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").unwrap(); }
                Behaviour::Refuses => { s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").unwrap(); }
                Behaviour::Works => {
                    s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nearly:").unwrap();
                    splice_test(s, TcpStream::connect(origin).unwrap());
                }
            }
        });
    });
    TestProxy { port, asked }
}

/// The listener with a stand-in for pf: each test client registers the
/// address it "meant" under its own local port before connecting.
struct Rig { listener: Listener, routing: Arc<Routing>, meant: Arc<Mutex<HashMap<u16, SocketAddrV4>>> }

fn rig(lines: &[String]) -> Rig {
    let routing = Routing::new(Table::parse(lines));
    let meant: Arc<Mutex<HashMap<u16, SocketAddrV4>>> = Arc::default();
    let lookup = meant.clone();
    let original: OriginalDestination = Arc::new(move |s: &TcpStream| {
        let port = s.peer_addr().ok()?.port();
        lookup.lock().unwrap().get(&port).copied()
    });
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

#[test]
fn socks5_carries_the_name_and_both_directions() {
    let site = origin();
    let proxy = socks_proxy(site.address, Behaviour::Works);
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
fn http_connect_carries_the_name_and_early_bytes() {
    let site = origin();
    let proxy = http_proxy(site.address, Behaviour::Works);
    let r = rig(&list(&[&format!("proxy:0 http localhost {}", proxy.port), "via:0:full:api.site.example"]));
    let mut app = r.open("api.site.example", 8443);
    round_trip(&mut app, "early:");
    assert_eq!(proxy.asked.recv_timeout(Duration::from_secs(5)).unwrap(), "api.site.example:8443");
}

#[test]
fn rules_pick_the_first_matching_proxy() {
    let site = origin();
    let socks = socks_proxy(site.address, Behaviour::Works);
    let http = http_proxy(site.address, Behaviour::Works);
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
    for (proxy, kind, expect) in [
        (socks_proxy(site.address, Behaviour::WantsPassword), "socks5", "用户名密码"),
        (socks_proxy(site.address, Behaviour::Refuses), "socks5", "拒绝"),
        (http_proxy(site.address, Behaviour::WantsPassword), "http", "用户名密码"),
        (http_proxy(site.address, Behaviour::Refuses), "http", "403"),
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
    let proxy = socks_proxy(site.address, Behaviour::Works);
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
    let proxy = socks_proxy(site.address, Behaviour::Works);
    let mut r = rig(&list(&[&format!("proxy:0 socks5 127.0.0.1 {}", proxy.port), "via:0:site.example"]));
    let mut app = r.open("site.example", 443);
    round_trip(&mut app, "");
    r.listener.stop();
    let mut buf = [0u8; 8];
    assert!(matches!(app.read(&mut buf), Ok(0) | Err(_)));
}
