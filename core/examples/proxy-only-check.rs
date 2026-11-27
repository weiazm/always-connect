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

        // Optional Hysteria2 end-to-end root check (§七十): when AC_HY2_BIN is set,
        // start a local Hysteria2 server, run ProxyOnly with a managed Hysteria2 proxy,
        // and connect as an app does: the system resolver gives our address, pf
        // sends the connection to our relay, the relay hands the name to the
        // managed client (as nobody), the client to the server, and the server's
        // ACL points the test name at the local echo site. Then stop, no leftovers.
        if let Ok(hy_bin) = std::env::var("AC_HY2_BIN") {
            if !hy_bin.is_empty() {
                run_hysteria_check(&hy_bin, site)?;
            }
        }
        run_egress_proxy_check(site)?;
        run_egress_local_check()?;
        Ok(())
    }

    /// Zero-proxy exit protection root check (§71 D2): with NO proxy servers
    /// configured, a protected site in proxy-only mode still keeps the DNS
    /// forwarder, 198.19.128.0/17 loopback route and pf anchor 301 active,
    /// captures the name into RouteVia::Local, and blocks when the local exit
    /// country does not match (or cannot be verified).
    fn run_egress_local_check() -> Result<(), String> {
        use alwaysconnect_core::egress_control::{EgressConfig, Group, ProbeHook, Unverified};
        use std::sync::Arc;

        stage("proxy-only zero-proxy local egress check");
        let work = std::env::temp_dir().join(format!("ac-proxy-only-local-egress-{}", std::process::id()));
        std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
        let net = network()?;

        // Return wrong country YY immediately on the bridge without sending any
        // external HTTP request. Even if the runner cannot reach port 443,
        // Unverified::Block still records a blocked verdict on path "local".
        let hook: ProbeHook = Arc::new(move |_req, peer| {
            *peer = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
            Some(b"HTTP/1.1 200 OK\r\n\r\nloc=YY\n".to_vec())
        });
        let egress_cfg = EgressConfig {
            enabled: true,
            prefetch: Some(0),
            groups: vec![Group {
                id: 1, name: "LocalOnlyCheck".into(), enabled: true,
                sites: vec!["apple.com".into()], expect: vec!["ZZ".into()],
                unverified: Unverified::Block, ..Default::default()
            }],
            ..Default::default()
        };
        // Empty rules: ZERO proxy servers!
        let mut session = ProxyOnly::start_with_egress(
            Vec::new(), net, &work, "check-local-egress".into(), 53, false, Some(egress_cfg), Some(hook),
        ).map_err(str::to_owned)?;
        let res = (|| -> Result<(), String> {
            session.routing().ok_or("local egress: no routing")?.treat_same_process_as_apps();
            flush();
            let resolved = resolve("www.apple.com");
            if !(resolved.len() == 1 && split_proxy::is_fake(resolved[0])) {
                return Err(format!("local egress: expected fake ip for protected name with 0 proxies, got {resolved:?}"));
            }
            let mut app = TcpStream::connect_timeout(&SocketAddr::from((resolved[0], 443)), Duration::from_secs(5))
                .map_err(|e| format!("local egress connect: {e}"))?;
            app.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = app.write_all(b"must-not-leave-locally");
            let mut got = [0u8; 16];
            if let Ok(n) = app.read(&mut got) {
                if n > 0 { return Err(format!("local egress wrong country forwarded {n} bytes!")); }
            }
            let status = session.egress_status();
            if !status.contains("\"state\":\"blocked\"") || !status.contains("\"path\":\"local\"") {
                return Err(format!("unexpected local egress status: {status}"));
            }
            println!("proxy-only zero-proxy local egress: captured into 198.19.128/17 via pf and blocked on path=local");
            Ok(())
        })();
        session.stop();
        flush();
        let after = resolve("www.apple.com");
        let anchor = command("/sbin/pfctl", &["-a", alwaysconnect_core::pf::PROXY_ANCHOR, "-s", "nat"]);
        let routes = command("/usr/sbin/netstat", &["-rn", "-f", "inet"]);
        let _ = std::fs::remove_dir_all(&work);
        res?;
        if entry_present() { return Err("local egress: DNS entry still there after stop".into()); }
        if after.iter().any(|ip| split_proxy::is_fake(*ip)) { return Err(format!("local egress: still fake ip after stop: {after:?}")); }
        if anchor.contains("rdr") { return Err(format!("local egress: anchor still has rules: {anchor}")); }
        if routes.lines().any(|l| l.starts_with("198.19.128/17")) { return Err("local egress: route still present".into()); }
        Ok(())
    }

    /// Proxy-only + exit protection root check (§71): a protected site routed
    /// through a local SOCKS5 proxy is checked before forwarding — allowed
    /// country passes traffic through pf -> relay -> SOCKS5 -> echo site;
    /// wrong country resets the app connection before any business bytes leave.
    fn run_egress_proxy_check(site: SocketAddr) -> Result<(), String> {
        use alwaysconnect_core::egress_control::{EgressConfig, Group, ProbeHook, Unverified};
        use std::sync::{Arc, Mutex};

        stage("proxy-only egress check");
        let work = std::env::temp_dir().join(format!("ac-proxy-only-egress-{}", std::process::id()));
        std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
        let (tx, asked) = mpsc::channel();
        let socks = socks5(site, tx).map_err(|e| e.to_string())?;
        let net = network()?;

        let country = Arc::new(Mutex::new("ZZ".to_string()));
        let c_hook = country.clone();
        let hook: ProbeHook = Arc::new(move |req, peer| {
            let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, req.port)).ok()?;
            s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
            *peer = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
            s.write_all(b"egress-probe").ok()?;
            let mut echo = [0u8; 12];
            s.read_exact(&mut echo).ok()?;
            if &echo != b"egress-probe" { return None; }
            let code = c_hook.lock().unwrap().clone();
            Some(format!("HTTP/1.1 200 OK\r\n\r\nloc={code}\n").into_bytes())
        });

        let egress_cfg = EgressConfig {
            enabled: true,
            prefetch: Some(0),
            groups: vec![Group {
                id: 1, name: "RootCheck".into(), enabled: true,
                sites: vec![SITE.into()], expect: vec!["ZZ".into()],
                unverified: Unverified::Block, ..Default::default()
            }],
            ..Default::default()
        };
        let lines = vec![format!("proxy:0 socks5 127.0.0.1 {socks}"), format!("via:0:domain:{SITE}")];
        let mut session = ProxyOnly::start_with_egress(
            lines, net, &work, "check-egress".into(), 53, false, Some(egress_cfg), Some(hook),
        ).map_err(str::to_owned)?;
        let res = (|| -> Result<(), String> {
            session.routing().ok_or("no routing")?.treat_same_process_as_apps();
            flush();
            let proxied = resolve(&format!("egress.{SITE}"));
            if !(proxied.len() == 1 && split_proxy::is_fake(proxied[0])) {
                return Err(format!("egress: system resolver did not give fake ip: {proxied:?}"));
            }
            // Allowed country ZZ: probe runs, then app connection succeeds.
            let mut app = TcpStream::connect_timeout(&SocketAddr::from((proxied[0], site.port())), Duration::from_secs(5))
                .map_err(|e| format!("egress allow connect: {e}"))?;
            app.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            app.write_all(b"egress-ok!").map_err(|e| e.to_string())?;
            let mut back = [0u8; 10];
            app.read_exact(&mut back).map_err(|e| format!("egress allow read: {e}"))?;
            if &back != b"egress-ok!" { return Err("egress allow wrong bytes".into()); }
            let _ = asked.recv_timeout(Duration::from_secs(2));
            let _ = asked.recv_timeout(Duration::from_secs(2));

            // Switch proxy exit to wrong country YY and update egress to invalidate cache.
            *country.lock().unwrap() = "YY".into();
            session.update_egress(Some(EgressConfig {
                enabled: true,
                prefetch: Some(0),
                groups: vec![Group {
                    id: 1, name: "RootCheck".into(), enabled: true,
                    sites: vec![SITE.into()], expect: vec!["ZZ".into()],
                    unverified: Unverified::Block, ..Default::default()
                }],
                ..Default::default()
            }));
            // Force epoch bump via rule update.
            session.update_rules(vec![format!("proxy:0 socks5 127.0.0.1 {socks}"), format!("via:0:domain:{SITE}")]);
            while asked.try_recv().is_ok() {}

            let mut blocked = TcpStream::connect_timeout(&SocketAddr::from((proxied[0], site.port())), Duration::from_secs(5))
                .map_err(|e| format!("egress block connect: {e}"))?;
            blocked.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = blocked.write_all(b"must-not-pass");
            let mut got = [0u8; 16];
            if let Ok(n) = blocked.read(&mut got) {
                if n > 0 { return Err(format!("egress wrong country forwarded {n} bytes!")); }
            }
            // Only the probe hit SOCKS5, never the business connection.
            let _ = asked.recv_timeout(Duration::from_secs(2)).map_err(|_| "egress block did not probe")?;
            if asked.recv_timeout(Duration::from_millis(200)).is_ok() {
                return Err("egress wrong country still opened business connection".into());
            }
            let status = session.egress_status();
            if !status.contains("\"state\":\"blocked\"") || !status.contains("\"path\":\"proxy:0\"") {
                return Err(format!("unexpected egress status: {status}"));
            }
            println!("proxy-only egress: allowed ZZ forwarded; wrong YY blocked before business connect");
            Ok(())
        })();
        session.stop();
        flush();
        let _ = std::fs::remove_dir_all(&work);
        res
    }

    fn run_hysteria_check(hy_bin: &str, site: SocketAddr) -> Result<(), String> {
        stage("hysteria2 proxy-only start");
        let work = std::env::temp_dir().join(format!("ac-proxy-only-hy2-{}", std::process::id()));
        std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
        // Make cert + key + pin
        let crt = work.join("server.crt");
        let key = work.join("server.key");
        let status = std::process::Command::new("/usr/bin/openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key.to_str().unwrap(), "-out", crt.to_str().unwrap(),
                "-days", "2", "-nodes", "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            ])
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
            .status().map_err(|e| format!("openssl: {e}"))?;
        if !status.success() { return Err("openssl cert gen failed".into()); }
        let der = std::process::Command::new("/usr/bin/openssl")
            .args(["x509", "-in", crt.to_str().unwrap(), "-outform", "DER"])
            .output().map_err(|e| format!("openssl der: {e}"))?.stdout;
        let mut sha = std::process::Command::new("/usr/bin/shasum")
            .args(["-a", "256"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
            .spawn().map_err(|e| format!("shasum: {e}"))?;
        sha.stdin.take().unwrap().write_all(&der).map_err(|e| e.to_string())?;
        let pin = String::from_utf8_lossy(&sha.wait_with_output().map_err(|e| e.to_string())?.stdout)
            .split_whitespace().next().unwrap_or("").to_ascii_lowercase();
        let port = 29443u16;
        let auth = "root-check-auth";
        let cfg = work.join("server.json");
        let log = work.join("server.log");
        // The server sends the test name to the local echo site (ACL hijack,
        // same port), lets the direct check reach loopback and refuses
        // everything else: nothing leaves the runner.
        std::fs::write(&cfg, serde_json::json!({
            "listen": format!("127.0.0.1:{port}"),
            "tls": { "cert": crt.to_str().unwrap(), "key": key.to_str().unwrap() },
            "auth": { "type": "password", "password": auth },
            "acl": { "inline": [format!("direct(suffix:{SITE}, *, 127.0.0.1)"), "direct(127.0.0.1)".to_string(), "reject(all)".to_string()] },
        }).to_string()).map_err(|e| e.to_string())?;
        let log_file = std::fs::File::create(&log).map_err(|e| e.to_string())?;
        let srv = std::process::Command::new(hy_bin)
            .args(["server", "-c", cfg.to_str().unwrap(), "--disable-update-check", "--log-format", "json"])
            .stdout(std::process::Stdio::null()).stderr(log_file)
            .spawn().map_err(|e| format!("spawn hysteria server: {e}"))?;
        struct KillOnDrop(std::process::Child);
        impl Drop for KillOnDrop { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let _srv_guard = KillOnDrop(srv);
        let ready = (0..40).any(|_| {
            if std::fs::read_to_string(&log).unwrap_or_default().contains("server up and running") { return true; }
            std::thread::sleep(Duration::from_millis(100));
            false
        });
        if !ready {
            let detail = std::fs::read_to_string(&log).unwrap_or_default();
            return Err(format!("hysteria server did not start: {}", detail.trim()));
        }

        split_proxy::hysteria::configure_binary(std::path::PathBuf::from(hy_bin), None, true);
        let net = network()?;
        let lines = vec![
            format!("proxy:0 hysteria2 127.0.0.1 {port} auth={auth} sni=localhost pin={pin}"),
            "vianet:0:203.0.113.0/24".into(),
            format!("via:0:domain:{SITE}"),
        ];
        // Bind a temporary loopback echo on 443 when free so Hysteria2 egress
        // probes (which dial target:443 through the managed client) complete a
        // full round-trip through the official server too (§71).
        let probe_443 = TcpListener::bind("127.0.0.1:443").ok().map(|l| {
            std::thread::spawn(move || for mut s in l.incoming().flatten() {
                std::thread::spawn(move || { let mut w = s.try_clone().unwrap(); let _ = io::copy(&mut s, &mut w); });
            });
            true
        }).unwrap_or(false);
        let hy_country = std::sync::Arc::new(std::sync::Mutex::new("ZZ".to_string()));
        let hy_country_hook = hy_country.clone();
        let hy_hook: alwaysconnect_core::egress_control::ProbeHook = std::sync::Arc::new(move |req, peer| {
            let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, req.port)).ok()?;
            s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
            *peer = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
            s.write_all(b"hy2-probe").ok()?;
            let mut echo = [0u8; 9];
            s.read_exact(&mut echo).ok()?;
            if &echo != b"hy2-probe" { return None; }
            let code = hy_country_hook.lock().unwrap().clone();
            Some(format!("HTTP/1.1 200 OK\r\n\r\nloc={code}\n").into_bytes())
        });
        let mut session = ProxyOnly::start_with_egress(
            lines.clone(), net, &work, "check-hy2".into(), 53, false, None, Some(hy_hook),
        ).map_err(str::to_owned)?;
        let spec = split_proxy::HysteriaSpec {
            host: "127.0.0.1".into(), ports: port.to_string(), auth: auth.into(),
            sni: Some("localhost".into()), pin_sha256: Some(pin), obfs: None, obfs_password: None,
            ech: None, up_mbps: None, down_mbps: None, hop_secs: None,
        };
        let wait_ready = std::time::Instant::now() + Duration::from_secs(10);
        while split_proxy::hysteria::shared().running_socks_for(&spec).is_none() {
            if std::time::Instant::now() >= wait_ready {
                session.stop();
                return Err("managed hysteria client did not become ready".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        stage("hysteria2 proxy-only traffic");
        flush();
        let proxied = resolve(&format!("www.{SITE}"));
        let traffic_res = (|| -> Result<(), String> {
            if !(proxied.len() == 1 && split_proxy::is_fake(proxied[0])) {
                return Err(format!("hysteria2: system resolver did not give fake ip: {proxied:?}"));
            }
            // Also verify direct-to-echo through the managed Hysteria2 client's local SOCKS5
            let local_socks = split_proxy::hysteria::shared().running_socks_for(&spec).ok_or("managed socks missing")?;
            let (mut s, _) = split_proxy::open_through(&local_socks, &split_proxy::Target::Ip(Ipv4Addr::LOCALHOST), site.port())?;
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            s.write_all(b"hy2-root-ok").map_err(|e| e.to_string())?;
            let mut got = [0u8; 11];
            s.read_exact(&mut got).map_err(|e| format!("read back: {e}"))?;
            if &got != b"hy2-root-ok" { return Err("wrong bytes back through hysteria2".into()); }
            println!("hysteria2: the managed client's local SOCKS5 reaches the echo site");
            // As an app: our address from the system resolver, pf, our relay,
            // the managed client, the server, the echo site.
            let mut app = TcpStream::connect_timeout(&SocketAddr::from((proxied[0], site.port())), Duration::from_secs(5))
                .map_err(|e| format!("hysteria2: app connect: {e}"))?;
            app.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
            app.write_all(b"hy2-app-ok!").map_err(|e| e.to_string())?;
            let mut back = [0u8; 11];
            app.read_exact(&mut back).map_err(|e| format!("hysteria2: app read back: {e}"))?;
            if &back != b"hy2-app-ok!" { return Err("hysteria2: wrong bytes back on the app path".into()); }
            println!("hysteria2: an app's connection by name went system resolver -> pf -> relay -> managed client -> server");

            // Now enable exit protection on the live Hysteria2 fastOpen path (§71).
            use alwaysconnect_core::egress_control::{EgressConfig, Group, Unverified};
            let egress_cfg = EgressConfig {
                enabled: true,
                prefetch: Some(0),
                groups: vec![Group {
                    id: 1, name: "Hy2Egress".into(), enabled: true,
                    sites: vec![SITE.into()], expect: vec!["ZZ".into()],
                    unverified: Unverified::Block, ..Default::default()
                }],
                ..Default::default()
            };
            session.update_egress(Some(egress_cfg));
            if probe_443 {
                // Allowed country ZZ through official Hysteria2 server -> app traffic passes.
                let mut ok_app = TcpStream::connect_timeout(&SocketAddr::from((proxied[0], site.port())), Duration::from_secs(5))
                    .map_err(|e| format!("hysteria2 egress allow connect: {e}"))?;
                ok_app.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
                ok_app.write_all(b"hy2-egress!").map_err(|e| e.to_string())?;
                let mut ok_back = [0u8; 11];
                ok_app.read_exact(&mut ok_back).map_err(|e| format!("hysteria2 egress allow read: {e}"))?;
                if &ok_back != b"hy2-egress!" { return Err("hysteria2 egress allow wrong bytes".into()); }
            }
            // Wrong country YY (or unverified if 443 busy) -> fastOpen Hysteria2 stream is NOT opened, 0 bytes forwarded.
            *hy_country.lock().unwrap() = "YY".into();
            session.update_rules(lines);
            let mut blocked = TcpStream::connect_timeout(&SocketAddr::from((proxied[0], site.port())), Duration::from_secs(5))
                .map_err(|e| format!("hysteria2 egress block connect: {e}"))?;
            blocked.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let _ = blocked.write_all(b"hy2-must-not-pass");
            let mut buf = [0u8; 16];
            if let Ok(n) = blocked.read(&mut buf) {
                if n > 0 { return Err(format!("hysteria2 egress wrong country forwarded {n} bytes!")); }
            }
            let st = session.egress_status();
            if !st.contains("\"state\":\"blocked\"") || !st.contains("\"path\":\"proxy:0\"") {
                return Err(format!("hysteria2 unexpected egress status: {st}"));
            }
            println!("hysteria2 + egress: fastOpen path gated cleanly (probe_443={probe_443}, wrong country blocked on proxy:0)");
            Ok(())
        })();
        stage("hysteria2 proxy-only stop");
        session.stop();
        flush();
        let anchor = command("/sbin/pfctl", &["-a", alwaysconnect_core::pf::PROXY_ANCHOR, "-s", "nat"]);
        let routes = command("/usr/sbin/netstat", &["-rn", "-f", "inet"]);
        let _ = std::fs::remove_dir_all(&work);
        traffic_res?;
        if split_proxy::hysteria::shared().running_socks_for(&spec).is_some() {
            return Err("managed hysteria client still registered after stop".into());
        }
        if entry_present() { return Err("hysteria2: DNS entry still there after stop".into()); }
        if anchor.contains("rdr") { return Err(format!("hysteria2: anchor still has rules: {anchor}")); }
        if routes.lines().any(|l| l.starts_with("198.19.128/17")) { return Err("hysteria2: route still present".into()); }
        println!("hysteria2 proxy-only: verified end-to-end and cleanly stopped");
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
