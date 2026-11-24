//! Egress protection's launch contract (DESIGN §66.5): with protection on,
//! openconnect runs in --script-tun mode through the gate program, keeps the
//! vpnc-script path on its command line, and finds a running controller.
use super::*;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;

fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

fn egress(enabled: bool) -> crate::egress_control::EgressConfig {
    use crate::egress_control::*;
    EgressConfig {
        enabled,
        groups: vec![Group { id: 1, name: "Work".into(), enabled: true, sites: vec!["a.example".into()], expect: vec!["ZZ".into()], ..Default::default() }],
    }
}

struct Run {
    engine: Engine,
    dir: PathBuf,
    terminal: Receiver<i32>,
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = std::fs::write(self.dir.join("exit"), "");
        self.engine.stop(false, false);
        std::thread::sleep(Duration::from_millis(50));
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run(drop_protection: bool, egress_on: bool, gate: Option<&str>) -> Run {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = loop {
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ac-egress-start-{}-{sequence}", std::process::id()));
        match std::fs::create_dir(&dir) {
            Ok(()) => break dir,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create egress fixture: {e}"),
        }
    };
    let cli = dir.join("openconnect");
    std::fs::write(
        &cli,
        r#"#!/bin/sh
root=$(dirname "$0")
printf 'control=%s\ntun=%s\n' "$AC_GATE_CONTROL" "$AC_GATE_TUN" > "$root/env"
printf '%s\n' "$@" > "$root/args.tmp" && mv "$root/args.tmp" "$root/args"
read -r credential
while [ ! -f "$root/exit" ]; do sleep 0.01; done
"#,
    )
    .unwrap();
    let pfctl = dir.join("pfctl");
    std::fs::write(&pfctl, "#!/bin/sh\ncat >/dev/null\necho 'Token : 123' >&2\n").unwrap();
    for f in [&cli, &pfctl] {
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let guard = Arc::new(Guard::new(network_guard::Settings { support_dir: dir.clone(), boot: Some("test".into()), grace: Duration::from_secs(120), pfctl: Some(pfctl.to_string_lossy().into()) }));
    guard.owner_attached();
    let (tx, terminal) = mpsc::channel();
    let engine = Engine::new(
        Config {
            no_routes: true,
            test_active: true,
            test_openconnect: Some(cli.to_string_lossy().into()),
            test_gate: gate.map(str::to_string),
            script_path: "/usr/bin/true".into(),
            support_dir: dir.to_string_lossy().into(),
            cookie_store_path: dir.join("cookie.json").to_string_lossy().into(),
            physical_if: "en0".into(),
            drop_protection,
            password: "p".into(),
            server: "https://vpn.example".into(),
            egress: Some(egress(egress_on)),
            ..Config::default()
        },
        Hooks {
            state: Box::new(|_, _| {}),
            terminal: Box::new(move |t| {
                let _ = tx.send(t);
            }),
            physical_network: Box::new(|_| Some(("192.168.1.1".into(), "en0".into()))),
            network_available: Box::new(|| true),
            local_dns: Box::new(|_| vec![]),
            system_roots: Box::new(|| None),
            stopped: Box::new(|| {}),
        },
        guard,
    );
    engine.start();
    Run { engine, dir, terminal }
}

fn args(r: &Run) -> Vec<String> {
    assert!(wait_until(|| r.dir.join("args").exists()), "openconnect never started");
    std::fs::read_to_string(r.dir.join("args")).unwrap().lines().map(str::to_string).collect()
}

#[test]
fn protection_on_runs_openconnect_through_the_gate() {
    let r = run(true, true, Some("/opt/test/alwaysconnect-gate"));
    let a = args(&r);
    assert!(a.contains(&"--script-tun".to_string()), "{a:?}");
    assert!(a.contains(&"--script='/opt/test/alwaysconnect-gate' '/usr/bin/true'".to_string()), "{a:?}");
    let env = std::fs::read_to_string(r.dir.join("env")).unwrap();
    assert!(env.contains("tun=utun"));
    let sock = r.dir.join("egress.sock");
    assert!(env.contains(&format!("control={}", sock.display())));
    // The controller is up and greets a gate with the groups and the marker.
    let s = UnixStream::connect(&sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert!(v["probe_alpn"].as_str().unwrap().starts_with("ac-probe-"));
    assert_eq!(v["groups"][0]["sites"][0], "a.example");
    assert!(r.engine.egress_status().contains("\"groups\""));
}

#[test]
fn protection_off_or_without_drop_protection_keeps_the_plain_tunnel() {
    for (drop, on) in [(true, false), (false, true)] {
        let r = run(drop, on, Some("/opt/test/alwaysconnect-gate"));
        let a = args(&r);
        assert!(!a.contains(&"--script-tun".to_string()), "drop={drop} on={on}: {a:?}");
        assert!(a.contains(&"--script='/usr/bin/true'".to_string()));
        assert_eq!(r.engine.egress_status(), "{\"running\":false}");
    }
}

#[test]
fn a_missing_gate_refuses_to_connect() {
    let r = run(true, true, None);
    assert_eq!(r.terminal.recv_timeout(Duration::from_secs(5)).unwrap(), Terminal::ComponentMissing as i32);
    assert!(!r.dir.join("args").exists(), "no unchecked tunnel");
}

#[test]
fn losing_the_gate_restarts_a_still_running_vpn_child() {
    let run = run(true, true, Some("/opt/test/alwaysconnect-gate"));
    args(&run);
    let generation = run.engine.shared.core.lock().unwrap().generation;
    let mut gate = BufReader::new(UnixStream::connect(run.dir.join("egress.sock")).unwrap());
    let mut policy = String::new();
    assert!(gate.read_line(&mut policy).unwrap() > 0);
    drop(gate);
    assert!(wait_until(|| run.engine.shared.core.lock().unwrap().generation > generation),
            "the VPN child outlived its gate and never started a new one");
}

#[test]
fn stale_gate_loss_and_manual_stop_do_not_start_another_vpn() {
    let run = run(true, true, Some("/opt/test/alwaysconnect-gate"));
    let _ = args(&run);
    let generation = run.engine.shared.core.lock().unwrap().generation;
    run.engine.send(Event::EgressGateLost(generation - 1));
    let (tx, rx) = mpsc::channel();
    run.engine.send(Event::Barrier(tx));
    rx.recv_timeout(Duration::from_secs(3)).unwrap();
    {
        let core = run.engine.shared.core.lock().unwrap();
        assert!(!core.gate_lost);
        assert_eq!(core.generation, generation);
    }
    run.engine.stop(false, false);
    run.engine.send(Event::EgressGateLost(generation));
    assert_eq!(run.terminal.recv_timeout(Duration::from_secs(5)).unwrap(), Terminal::StoppedManual as i32);
    assert_eq!(run.engine.shared.core.lock().unwrap().generation, generation);
}
