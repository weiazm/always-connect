//! Real-pf check for proxied sites (DESIGN.md §六十九), run as root by
//! scripts/proxy-redirect-test.sh on the CI Mac. The production pieces —
//! the loopback route (DirectRoutes, its own journal), the pf anchor
//! (Guard::proxy_redirect), the listener with pf's DIOCNATLOOK — carry an
//! app connection to a proxied name through a local SOCKS5 and a local
//! HTTP CONNECT proxy to a local site. Then: UDP to the range is refused
//! at once, a stopped listener means refused (never direct), and cleanup
//! leaves no route and an empty anchor. Touches only 198.19.128.0/17,
//! 203.0.113.0/24 (TEST-NET-3) and loopback; everything is taken out again on every path.

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

    /// CONNECT (by name or address, always to the local site) and UDP
    /// ASSOCIATE (each datagram comes back as "echo:<payload>").
    fn socks5(site: SocketAddr, asked: mpsc::Sender<String>) -> io::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        std::thread::spawn(move || for mut s in listener.incoming().flatten() {
            let asked = asked.clone();
            std::thread::spawn(move || -> io::Result<()> {
                let mut b = [0u8; 2]; s.read_exact(&mut b)?;
                let mut m = vec![0u8; b[1] as usize]; s.read_exact(&mut m)?;
                s.write_all(&[5, 0])?;
                let mut r = [0u8; 4]; s.read_exact(&mut r)?;
                let target = if r[3] == 3 {
                    let mut n = [0u8; 1]; s.read_exact(&mut n)?;
                    let mut name = vec![0u8; n[0] as usize + 2]; s.read_exact(&mut name)?;
                    format!("{}:{}", String::from_utf8_lossy(&name[..name.len() - 2]), u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]))
                } else {
                    let mut a = [0u8; 6]; s.read_exact(&mut a)?;
                    format!("{}.{}.{}.{}:{}", a[0], a[1], a[2], a[3], u16::from_be_bytes([a[4], a[5]]))
                };
                if r[1] == 3 {
                    let relay = UdpSocket::bind("127.0.0.1:0")?;
                    let mut reply = vec![5, 0, 0, 1, 0, 0, 0, 0];
                    reply.extend_from_slice(&relay.local_addr()?.port().to_be_bytes());
                    s.write_all(&reply)?;
                    let asked = asked.clone();
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 2048];
                        while let Ok((n, from)) = relay.recv_from(&mut buf) {
                            let header = match buf[3] { 1 => 10, 3 => 7 + buf[4] as usize, _ => continue };
                            let _ = asked.send("socks5 udp".to_owned());
                            let mut answer = buf[..header].to_vec();
                            answer.extend_from_slice(b"echo:");
                            answer.extend_from_slice(&buf[header..n]);
                            let _ = relay.send_to(&answer, from);
                        }
                    });
                    let mut rest = Vec::new();
                    let _ = s.read_to_end(&mut rest);
                    return Ok(());
                }
                let _ = asked.send(format!("socks5 {target}"));
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
        if table.lines().any(|l| l.starts_with("198.19.128/17") || l.starts_with("203.0.113/24")) { return Err("route still present".into()); }
        Ok(())
    }

    fn load(guard: &Guard, tcp: Option<u16>, udp: Option<u16>) -> Result<(), String> {
        let text = alwaysconnect_core::pf::proxy_redirect(tcp, udp, &[NETWORK.to_owned()]);
        guard.proxy_redirect(Some(&text)).map_err(|e| format!("pf load: {e}"))
    }

    fn udp_answer(ip: std::net::Ipv4Addr, port: u16) -> io::Result<Vec<u8>> {
        let udp = UdpSocket::bind("0.0.0.0:0")?;
        udp.connect(SocketAddr::from((ip, port)))?;
        udp.set_read_timeout(Some(Duration::from_millis(300)))?;
        let mut buf = [0u8; 64];
        let mut last = io::Error::from(io::ErrorKind::TimedOut);
        // The first datagrams go while the association is set up.
        for _ in 0..20 {
            udp.send(b"quic?")?;
            match udp.recv(&mut buf) {
                Ok(n) => return Ok(buf[..n].to_vec()),
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => return Err(e),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// TEST-NET-3: never a real destination, safe to route on the runner.
    const NETWORK: &str = "203.0.113.0/24";

    fn check(guard: &Guard, routes: &DirectRoutes) -> Result<(), String> {
        let site = echo_site().map_err(|e| e.to_string())?;
        let (tx, asked) = mpsc::channel();
        let socks = socks5(site, tx.clone()).map_err(|e| e.to_string())?;
        let http = http(site, tx).map_err(|e| e.to_string())?;
        let routing = Routing::new(Table::parse(&[
            format!("proxy:0 socks5 127.0.0.1 {socks}"), "via:0:domain:socks.example".into(), format!("vianet:0:{NETWORK}"),
            format!("proxy:1 http 127.0.0.1 {http}"), "via:1:full:http.example".into(),
        ]));
        // The stand-in proxies live in this process, like the apps here.
        routing.treat_same_process_as_apps();
        let original = split_proxy::pf_original_destination().map_err(|e| format!("/dev/pf: {e}"))?;
        let mut listener = Listener::start(routing.clone(), original).map_err(|e| e.to_string())?;
        if !routes.add(&[split_proxy::FAKE_NETWORK.into(), NETWORK.into()], "127.0.0.1") { return Err("route add failed".into()); }
        load(guard, Some(listener.port()), Some(listener.udp_port()))?;
        println!("{}", command("/sbin/pfctl", &["-a", alwaysconnect_core::pf::PROXY_ANCHOR, "-s", "nat"]).trim());

        stage("tcp exchanges");
        let socks_ip = routing.answer("www.socks.example").ok_or("no answer")?;
        exchange(socks_ip, 443)?;
        let seen = asked.recv_timeout(Duration::from_secs(5)).map_err(|_| "socks proxy not asked")?;
        if seen != "socks5 www.socks.example:443" { return Err(format!("socks proxy asked {seen}")); }
        let http_ip = routing.answer("http.example").ok_or("no answer")?;
        exchange(http_ip, 8080)?;
        let seen = asked.recv_timeout(Duration::from_secs(5)).map_err(|_| "http proxy not asked")?;
        if seen != "http http.example:8080" { return Err(format!("http proxy asked {seen}")); }
        exchange(std::net::Ipv4Addr::new(203, 0, 113, 9), 7)?;
        let seen = asked.recv_timeout(Duration::from_secs(5)).map_err(|_| "socks proxy not asked for the network")?;
        if seen != "socks5 203.0.113.9:7" { return Err(format!("socks proxy asked {seen}")); }
        println!("SOCKS5 and HTTP CONNECT carried names and a written network through pf");

        // With redirected connections open, the states are bound to lo0 and
        // the pre-login check accepts them (a floating state stopped the
        // next login on the real Mac).
        stage("states with open proxied connections");
        let held = TcpStream::connect_timeout(&SocketAddr::from((socks_ip, 443)), Duration::from_secs(5)).map_err(|e| e.to_string())?;
        std::thread::sleep(Duration::from_millis(200));
        let states = command("/sbin/pfctl", &["-s", "states"]);
        let ours: Vec<&str> = states.lines().filter(|l| l.contains("198.19.128.")).collect();
        if ours.is_empty() || ours.iter().any(|l| !l.trim_start().starts_with("lo0 ")) {
            return Err(format!("redirected states are not bound to lo0: {ours:?}"));
        }
        let policy = alwaysconnect_core::pf_verify::BlockingPolicy::new("en0", &[], 443, false, &[]).map_err(|e| format!("{e:?}"))?;
        // Only our states are judged: the runner's own are not this check's.
        alwaysconnect_core::pf_verify::check_states(&policy, |args| {
            std::process::Command::new("/sbin/pfctl").args(args).output().map(|o| {
                let text = String::from_utf8_lossy(&o.stdout).into_owned();
                let mut kept = String::new();
                let mut keep = false;
                for line in text.lines() {
                    if !line.starts_with(char::is_whitespace) { keep = line.contains("198.19.128."); }
                    if keep { kept.push_str(line); kept.push('\n'); }
                }
                alwaysconnect_core::pf_verify::PfOutput { stdout: kept, stderr: String::from_utf8_lossy(&o.stderr).into() }
            })
        }).map_err(|e| format!("pre-login state check refused open proxied connections: {e:?}"))?;
        drop(held);
        println!("redirected states sit on lo0 and pass the pre-login state check");

        stage("udp through socks5");
        let answer = match udp_answer(socks_ip, 443) {
            Ok(answer) => answer,
            Err(e) => {
                // Where it stopped: pf's record of the flow, and whether the
                // datagram reached the proxy at all.
                let probe = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
                probe.connect(SocketAddr::from((socks_ip, 443))).map_err(|e| e.to_string())?;
                let _ = probe.send(b"probe");
                std::thread::sleep(Duration::from_millis(300));
                let local = probe.local_addr().map_err(|e| e.to_string())?;
                let look = split_proxy::pf_original_destination().ok().and_then(|o| match local {
                    SocketAddr::V4(v4) => o(split_proxy::Proto::Udp, v4, std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, listener.udp_port())),
                    _ => None,
                });
                let reached: Vec<String> = asked.try_iter().collect();
                println!("{}", command("/sbin/pfctl", &["-s", "state"]).lines().filter(|l| l.contains("198.19.") || l.contains(&listener.udp_port().to_string())).collect::<Vec<_>>().join("\n"));
                return Err(format!("UDP through SOCKS5: {e}; app source {local}; pf original {look:?}; proxy saw {reached:?}"));
            }
        };
        if answer != b"echo:quic?" { return Err(format!("UDP answer {answer:?}")); }
        println!("UDP went through the SOCKS5 association and came back from the address the app used");

        // UDP not carried (no SOCKS5 UDP redirect): refused at once.
        stage("udp refused");
        load(guard, Some(listener.port()), None)?;
        let started = Instant::now();
        match udp_answer(http_ip, 443) {
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => println!("UDP refused after {:?}", started.elapsed()),
            other => return Err(format!("UDP was not refused: {other:?}")),
        }

        // No listener: the redirect stays, connections are refused.
        stage("stop listener");
        listener.stop();
        stage("connect without listener");
        let started = Instant::now();
        match TcpStream::connect_timeout(&SocketAddr::from((socks_ip, 443)), Duration::from_secs(5)) {
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => println!("stopped listener: refused after {:?}", started.elapsed()),
            other => return Err(format!("expected refusal with no listener, got {other:?}")),
        }
        Ok(())
    }
}
