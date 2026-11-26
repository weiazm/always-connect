//! Real-Mac check for proxies with Cisco off (DESIGN.md §69.20), run as root
//! by scripts/proxy-redirect-test.sh on the CI Mac. The production session
//! (core/src/proxy_only.rs): our DNS entry in configd makes the system
//! resolver ask our forwarder; a proxied name comes back as our address and
//! an app's connection to it reaches a local SOCKS5 proxy through the
//! loopback route and pf; other names still resolve through the runner's own
//! DNS; stopping removes the entry, the route and the redirect. Touches only
//! 198.19.128.0/17, loopback and our own configd key.

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(match macos::run() {
        Ok(()) => { println!("proxy-only-check: ok"); 0 }
        Err(e) => { eprintln!("proxy-only-check: FAILED: {e}"); 1 }
    });
}

#[cfg(not(target_os = "macos"))]
fn main() { eprintln!("macOS only"); }

#[cfg(target_os = "macos")]
mod macos {
    use alwaysconnect_core::network_guard::{self, Settings};
    use alwaysconnect_core::proxy_only::{Network, ProxyOnly, DNS_SERVICE};
    use alwaysconnect_core::split_proxy;
    use std::io::{self, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
    use std::sync::mpsc;
    use std::time::Duration;

    static STAGE: std::sync::Mutex<&'static str> = std::sync::Mutex::new("start");
    fn stage(name: &'static str) { *STAGE.lock().unwrap() = name; println!("-- {name}"); }

    const SITE: &str = "proxied-only-check.example.com";

    fn command(program: &str, args: &[&str]) -> String {
        std::process::Command::new(program).args(args).output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr)).unwrap_or_default()
    }

    fn echo_site() -> io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        std::thread::spawn(move || for mut s in listener.incoming().flatten() {
            std::thread::spawn(move || { let mut w = s.try_clone().unwrap(); let _ = io::copy(&mut s, &mut w); });
        });
        Ok(address)
    }

    /// SOCKS5 CONNECT only, always to the local site; reports what it was asked.
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
                    format!("{}:{}", String::from_utf8_lossy(&name[..name.len() - 2]),
                            u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]))
                } else {
                    let mut a = [0u8; 6]; s.read_exact(&mut a)?;
                    format!("{}.{}.{}.{}:{}", a[0], a[1], a[2], a[3], u16::from_be_bytes([a[4], a[5]]))
                };
                let _ = asked.send(target);
                s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])?;
                let site = TcpStream::connect(site)?;
                let (mut a, mut b) = (s.try_clone()?, site.try_clone()?);
                std::thread::spawn(move || { let mut s = s; let mut site = site; let _ = io::copy(&mut s, &mut site); let _ = site.shutdown(Shutdown::Write); });
                let _ = io::copy(&mut b, &mut a);
                let _ = a.shutdown(Shutdown::Write);
                Ok(())
            });
        });
        Ok(port)
    }

    fn flush() {
        let _ = command("/usr/bin/dscacheutil", &["-flushcache"]);
        let _ = command("/usr/bin/killall", &["-HUP", "mDNSResponder"]);
        std::thread::sleep(Duration::from_millis(800));
    }

    /// Through the system resolver, as any app does.
    fn resolve(name: &str) -> Vec<Ipv4Addr> {
        (name, 443).to_socket_addrs().map(|it| it.filter_map(|a| match a.ip() { IpAddr::V4(v4) => Some(v4), _ => None }).collect())
            .unwrap_or_default()
    }

    fn entry_present() -> bool {
        let mut child = std::process::Command::new("/usr/sbin/scutil")
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(format!("show State:/Network/Service/{DNS_SERVICE}/DNS\nquit\n").as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stdout).contains("127.0.0.1")
    }

    /// The runner's own network: the default route's interface and its DNS.
    fn network() -> Result<Network, String> {
        let route = command("/sbin/route", &["-n", "get", "default"]);
        let interface = route.lines().find_map(|l| l.trim().strip_prefix("interface: ")).map(str::to_owned)
            .ok_or("no default interface")?;
        let dns: Vec<String> = command("/usr/sbin/scutil", &["--dns"]).lines()
            .filter_map(|l| l.trim().strip_prefix("nameserver[0] : ").map(str::to_owned))
            .filter(|ip| ip.parse::<Ipv4Addr>().is_ok_and(|v| !v.is_loopback())).take(1).collect();
        if dns.is_empty() { return Err("no DNS server on the runner".into()); }
        println!("network: {interface}, DNS {dns:?}");
        Ok(Network { interface: Some(interface), dns })
    }

    pub fn run() -> Result<(), String> {
        if unsafe { libc::geteuid() } != 0 { return Err("run as root".into()); }
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(60));
            eprintln!("proxy-only-check: stuck at {}", STAGE.lock().unwrap());
            std::process::exit(1);
        });
        let work = std::env::temp_dir().join(format!("ac-proxy-only-{}", std::process::id()));
        std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
        network_guard::init(Settings { support_dir: work.clone(), boot: Some("check".into()),
                                       grace: Duration::from_secs(120), pfctl: Some("/sbin/pfctl".into()) });
        let site = echo_site().map_err(|e| e.to_string())?;
        let (tx, asked) = mpsc::channel();
        let socks = socks5(site, tx).map_err(|e| e.to_string())?;
        let network = network()?;
        stage("start");
        let lines = vec![format!("proxy:0 socks5 127.0.0.1 {socks}"), format!("via:0:domain:{SITE}")];
        let mut session = ProxyOnly::start(lines, network, &work, "check".into(), 53, false).map_err(str::to_owned)?;
        let result = check(&session, &asked);
        stage("stop");
        session.stop();
        flush();
        let after = resolve(&format!("www.{SITE}"));
        let anchor = command("/sbin/pfctl", &["-a", alwaysconnect_core::pf::PROXY_ANCHOR, "-s", "nat"]);
        let routes = command("/usr/sbin/netstat", &["-rn", "-f", "inet"]);
        let _ = std::fs::remove_dir_all(&work);
        result?;
        if entry_present() { return Err("the DNS entry is still there after stop".into()); }
        if after.iter().any(|ip| split_proxy::is_fake(*ip)) { return Err(format!("still our address after stop: {after:?}")); }
        if anchor.contains("rdr") { return Err(format!("anchor still has rules: {anchor}")); }
        if routes.lines().any(|l| l.starts_with("198.19.128/17")) { return Err("route still present".into()); }
        println!("stopped: no DNS entry, no route, empty anchor, the name is the network's again");
        Ok(())
    }

    fn check(session: &ProxyOnly, asked: &mpsc::Receiver<String>) -> Result<(), String> {
        // The stand-in proxy lives in this process, like the app here.
        session.routing().ok_or("no proxied sites")?.treat_same_process_as_apps();
        stage("dns entry");
        if !entry_present() { return Err("our DNS entry is not in configd".into()); }
        println!("{}", command("/usr/sbin/scutil", &["--dns"]).lines().take(8).collect::<Vec<_>>().join("\n"));
        stage("system resolver");
        flush();
        let proxied = resolve(&format!("www.{SITE}"));
        if !(proxied.len() == 1 && split_proxy::is_fake(proxied[0])) {
            return Err(format!("the system resolver did not give our address: {proxied:?}"));
        }
        println!("www.{SITE} -> {} through the system resolver", proxied[0]);
        let plain = resolve("www.apple.com");
        if plain.is_empty() || plain.iter().any(|ip| split_proxy::is_fake(*ip)) {
            return Err(format!("an ordinary name did not resolve through the network's DNS: {plain:?}"));
        }
        println!("www.apple.com -> {plain:?} (the network's DNS, through our forwarder)");
        stage("connection through the proxy");
        let mut app = TcpStream::connect_timeout(&SocketAddr::from((proxied[0], 443)), Duration::from_secs(5))
            .map_err(|e| format!("connect: {e}"))?;
        app.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        app.write_all(b"proxy only").map_err(|e| e.to_string())?;
        let mut got = [0u8; 10];
        app.read_exact(&mut got).map_err(|e| format!("read back: {e}"))?;
        if &got != b"proxy only" { return Err("wrong bytes back".into()); }
        let seen = asked.recv_timeout(Duration::from_secs(5)).map_err(|_| "the proxy was not asked")?;
        if seen != format!("www.{SITE}:443") { return Err(format!("the proxy was asked {seen}")); }
        println!("the app's connection went through the SOCKS5 proxy by name");
        Ok(())
    }
}
