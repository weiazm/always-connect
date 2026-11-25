//! Real-pf check for proxied sites (DESIGN.md §六十九), run as root by
//! scripts/proxy-redirect-test.sh on the CI Mac. The production pieces —
//! the loopback route (DirectRoutes, its own journal), the pf anchor
//! (Guard::proxy_redirect), the listener with pf's DIOCNATLOOK — carry an
//! app connection to a proxied name through a local SOCKS5 and a local
//! HTTP CONNECT proxy to a local site. Then: UDP to the range is refused
//! at once, a stopped listener means refused (never direct), and cleanup
//! leaves no route and an empty anchor. Touches only 198.19.128.0/17 and
//! loopback; everything is taken out again on every path.

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(match macos::run() { Ok(()) => { println!("proxy-redirect-check: ok"); 0 } Err(e) => { eprintln!("proxy-redirect-check: FAILED: {e}"); 1 } });
}

#[cfg(not(target_os = "macos"))]
fn main() { eprintln!("macOS only"); }

#[cfg(target_os = "macos")]
mod macos {
    use alwaysconnect_core::direct_routes::DirectRoutes;
    use alwaysconnect_core::network_guard::{Guard, Settings};
    use alwaysconnect_core::split_proxy::{self, Listener, Routing, Table};
    use std::io::{self, Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    static STAGE: std::sync::Mutex<&'static str> = std::sync::Mutex::new("start");
    fn stage(name: &'static str) { *STAGE.lock().unwrap() = name; println!("-- {name}"); }

    fn echo_site() -> io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        std::thread::spawn(move || for mut s in listener.incoming().flatten() {
            std::thread::spawn(move || { let mut w = s.try_clone().unwrap(); let _ = io::copy(&mut s, &mut w); });
        });
        Ok(address)
    }

    fn splice(a: TcpStream, b: TcpStream) {
        let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
        std::thread::spawn(move || { let (mut a, mut b) = (a, b); let _ = io::copy(&mut a, &mut b); let _ = b.shutdown(Shutdown::Write); });
        std::thread::spawn(move || { let _ = io::copy(&mut b2, &mut a2); let _ = a2.shutdown(Shutdown::Write); });
    }

    fn socks5(site: SocketAddr, asked: mpsc::Sender<String>) -> io::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        std::thread::spawn(move || for mut s in listener.incoming().flatten() {
            let asked = asked.clone();
            std::thread::spawn(move || -> io::Result<()> {
                let mut b = [0u8; 2]; s.read_exact(&mut b)?;
                let mut m = vec![0u8; b[1] as usize]; s.read_exact(&mut m)?;
                s.write_all(&[5, 0])?;
                let mut r = [0u8; 5]; s.read_exact(&mut r)?;
                let mut name = vec![0u8; r[4] as usize + 2]; s.read_exact(&mut name)?;
                let p = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
                let _ = asked.send(format!("socks5 {}:{p}", String::from_utf8_lossy(&name[..name.len() - 2])));
                s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])?;
                splice(s, TcpStream::connect(site)?);
                Ok(())
            });
        });
        Ok(port)
    }

    fn http(site: SocketAddr, asked: mpsc::Sender<String>) -> io::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        std::thread::spawn(move || for mut s in listener.incoming().flatten() {
            let asked = asked.clone();
            std::thread::spawn(move || -> io::Result<()> {
                let mut head = Vec::new(); let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") { s.read_exact(&mut byte)?; head.push(byte[0]); }
                let line = String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_owned();
                let _ = asked.send(format!("http {}", line.split_whitespace().nth(1).unwrap_or("")));
                s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
                splice(s, TcpStream::connect(site)?);
                Ok(())
            });
        });
        Ok(port)
    }

    fn exchange(ip: std::net::Ipv4Addr, port: u16) -> Result<(), String> {
        let mut app = TcpStream::connect_timeout(&SocketAddr::from((ip, port)), Duration::from_secs(5))
            .map_err(|e| format!("connect {ip}:{port}: {e}"))?;
        app.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        app.write_all(b"through pf").map_err(|e| e.to_string())?;
        let mut got = [0u8; 10];
        app.read_exact(&mut got).map_err(|e| format!("read back: {e}"))?;
        if &got != b"through pf" { return Err("wrong bytes back".into()); }
        Ok(())
    }

    fn command(program: &str, args: &[&str]) -> String {
        std::process::Command::new(program).args(args).output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr)).unwrap_or_default()
    }

    pub fn run() -> Result<(), String> {
        if unsafe { libc::geteuid() } != 0 { return Err("run as root".into()); }
        // A stuck step must not hold the runner: dump every thread's stack
        // (sample, with this debug build's symbols) and fail.
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(45));
            eprintln!("proxy-redirect-check: stuck at {}", STAGE.lock().unwrap());
            let pid = std::process::id().to_string();
            eprintln!("{}", command("/usr/bin/sample", &[&pid, "1", "-mayDie"]));
            std::process::exit(1);
        });
        let work = std::env::temp_dir().join(format!("ac-proxy-check-{}", std::process::id()));
        std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
        let guard = Guard::new(Settings { support_dir: work.clone(), boot: Some("check".into()), grace: Duration::from_secs(120), pfctl: Some("/sbin/pfctl".into()) });
        let routes = DirectRoutes::new(work.join("proxy-routes"), "check".into(), false);
        let result = check(&guard, &routes);
        stage("cleanup");
        // Always taken out, also after a failure.
        let pf = guard.proxy_redirect(None);
        let route = routes.remove_all();
        let left = command("/sbin/pfctl", &["-a", alwaysconnect_core::pf::PROXY_ANCHOR, "-s", "nat"]);
        let table = command("/usr/sbin/netstat", &["-rn", "-f", "inet"]);
        let _ = std::fs::remove_dir_all(&work);
        result?;
        pf.map_err(|e| format!("redirect removal: {e}"))?;
        if !route { return Err("route removal not confirmed".into()); }
        if left.contains("rdr") { return Err(format!("anchor still has rules: {left}")); }
        if table.lines().any(|l| l.starts_with("198.19.128/17") || l.starts_with("198.19.128.0/17")) { return Err("route still present".into()); }
        Ok(())
    }

    fn check(guard: &Guard, routes: &DirectRoutes) -> Result<(), String> {
        let site = echo_site().map_err(|e| e.to_string())?;
        let (tx, asked) = mpsc::channel();
        let socks = socks5(site, tx.clone()).map_err(|e| e.to_string())?;
        let http = http(site, tx).map_err(|e| e.to_string())?;
        let routing = Routing::new(Table::parse(&[
            format!("proxy:0 socks5 127.0.0.1 {socks}"), "via:0:domain:socks.example".into(),
            format!("proxy:1 http 127.0.0.1 {http}"), "via:1:full:http.example".into(),
        ]));
        let original = split_proxy::pf_original_destination().map_err(|e| format!("/dev/pf: {e}"))?;
        let mut listener = Listener::start(routing.clone(), original).map_err(|e| e.to_string())?;
        if !routes.add(&[split_proxy::FAKE_NETWORK.into()], "127.0.0.1") { return Err("route add failed".into()); }
        guard.proxy_redirect(Some(listener.port())).map_err(|e| format!("pf load: {e}"))?;
        println!("{}", command("/sbin/pfctl", &["-a", alwaysconnect_core::pf::PROXY_ANCHOR, "-s", "nat"]).trim());

        stage("socks5 exchange");
        let socks_ip = routing.answer("www.socks.example").ok_or("no answer")?;
        exchange(socks_ip, 443)?;
        let seen = asked.recv_timeout(Duration::from_secs(5)).map_err(|_| "socks proxy not asked")?;
        if seen != "socks5 www.socks.example:443" { return Err(format!("socks proxy asked {seen}")); }
        let http_ip = routing.answer("http.example").ok_or("no answer")?;
        exchange(http_ip, 8080)?;
        let seen = asked.recv_timeout(Duration::from_secs(5)).map_err(|_| "http proxy not asked")?;
        if seen != "http http.example:8080" { return Err(format!("http proxy asked {seen}")); }
        println!("SOCKS5 and HTTP CONNECT carried the names through pf");

        // UDP (QUIC) to the range: refused at once, not left to time out.
        let udp = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        udp.connect(SocketAddr::from((socks_ip, 443))).map_err(|e| e.to_string())?;
        udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let started = Instant::now();
        let _ = udp.send(b"quic?");
        let mut buf = [0u8; 16];
        match udp.recv(&mut buf) {
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => println!("UDP refused after {:?}", started.elapsed()),
            other => return Err(format!("UDP to the range was not refused: {other:?}")),
        }

        // No listener: the redirect stays, connections are refused.
        stage("stop listener");
        listener.stop();
        stage("reload redirect");
        guard.proxy_redirect(None).map_err(|e| e.to_string())?;
        guard.proxy_redirect(Some(listener.port())).map_err(|e| e.to_string())?;
        stage("connect without listener");
        let started = Instant::now();
        match TcpStream::connect_timeout(&SocketAddr::from((socks_ip, 443)), Duration::from_secs(5)) {
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => println!("stopped listener: refused after {:?}", started.elapsed()),
            other => return Err(format!("expected refusal with no listener, got {other:?}")),
        }
        Ok(())
    }
}
