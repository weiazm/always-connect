//! The kill switch for a tunnel the service does not run itself: the
//! Cisco engine (DESIGN.md §二十一; moved from Swift to Rust in §32.12).
//! Cisco owns the tunnel; the App reports what it sees (up → connected,
//! lost → blocking, manual disconnect → off) and this asks the network
//! gate for the matching set. While connected it also watches the tunnel
//! interface itself (routing-socket events), so a drop is blocked at once
//! even with no App.
//!
//! - connected: physical egress passes (Cisco routes the company's
//!   split-exclude networks out the physical interface by policy).
//! - blocking: restore the strict login set for the confirmed carrier
//!   and LAN; DNS and tunnel bypasses are disabled.

use crate::network_guard::{self, Guard, Inputs, CISCO_HOLDER};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

pub const OFF: i32 = 0;
pub const CONNECTED: i32 = 1;
pub const BLOCKING: i32 = 2;

const WATCH: Duration = Duration::from_secs(2);

struct State {
    verified_login: Option<u64>,
    /// Watchdog generation; Some while one runs.
    watch: Option<u64>,
    /// Writing to this wakes the watchdog to end.
    watch_stop: Option<std::os::fd::OwnedFd>,
    watch_generation: u64,
}

pub struct KillSwitch {
    guard: Arc<Guard>,
    state: Mutex<State>,
    wake: Condvar,
}

static SHARED: OnceLock<Arc<KillSwitch>> = OnceLock::new();

pub fn shared(guard: Arc<Guard>) -> Arc<KillSwitch> {
    SHARED.get_or_init(|| Arc::new(KillSwitch::new(guard))).clone()
}

fn interface_exists(name: &str) -> bool {
    std::ffi::CString::new(name).map(|c| unsafe { libc::if_nametoindex(c.as_ptr()) } != 0).unwrap_or(false)
}

/// The interface the routing table uses toward `ip` (the physical one for
/// a gateway Cisco pinned a host route to), never a tunnel.
pub fn interface_toward(ip: &str) -> Option<String> {
    crate::connections::route_interface(ip).filter(|n| !n.is_empty() && !n.starts_with("utun"))
}

/// IPv4 "a.b.c.d/n" (as the App's isValidCIDR: four numbers 0-255, n 0-32).
pub fn is_cidr(s: &str) -> bool {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 || !parts[1].parse::<u32>().is_ok_and(|b| b <= 32) {
        return false;
    }
    let octets: Vec<&str> = parts[0].split('.').collect();
    octets.len() == 4 && octets.iter().all(|o| o.parse::<u32>().is_ok_and(|n| n <= 255))
}

impl KillSwitch {
    pub fn new(guard: Arc<Guard>) -> KillSwitch {
        KillSwitch {
            guard,
            state: Mutex::new(State {
                verified_login: None,
                watch: None,
                watch_stop: None,
                watch_generation: 0,
            }),
            wake: Condvar::new(),
        }
    }

    /// (applied, message); on failure the message is the panel's red pf line.
    pub fn set(self: &Arc<Self>, mode: i32, tunnel_if: &str, gateway_ips: &[String]) -> (bool, String) {
        let mut s = self.state.lock().unwrap();
        let result = match mode {
            OFF => {
                self.disarm_locked(&mut s);
                if self.is_off() { Ok(()) } else { Err("网络仍在拦截，请使用恢复直连".into()) }
            }
            BLOCKING => self.block(&mut s).map(|generation| s.verified_login = Some(generation)),
            CONNECTED => self.connected(&mut s, tunnel_if, gateway_ips),
            _ => Err("未知的断线保护模式".into()),
        };
        match result {
            Ok(()) => (true, String::new()),
            Err(problem) => (false, problem),
        }
    }

    pub fn refresh_allow_networks(self: &Arc<Self>) {
        let _s = self.state.lock().unwrap();
        let Ok(current) = self.login_inputs() else { return };
        let Some(port) = current.login_port else { return };
        let mut inputs = current.clone();
        inputs.allow_networks = Inputs::login(&current.physical_if, Vec::new(), port, current.login_udp).allow_networks;
        if inputs != current {
            let connected = !current.tunnel_if.is_empty();
            let _ = self.guard.apply_cisco_if_held(&current, connected, &inputs);
        }
    }

    pub fn is_off(&self) -> bool {
        self.guard.holder().as_deref() != Some(CISCO_HOLDER)
    }

    /// (tunnel, gateways, physical) while armed.
    pub fn snapshot(&self) -> Option<(String, Vec<String>, String)> {
        let inputs = self.login_inputs().ok()?;
        (!inputs.tunnel_if.is_empty()).then_some((inputs.tunnel_if, inputs.gateway_ips, inputs.physical_if))
    }

    /// Manual disconnect, protection off, or the gate's grace ended:
    /// forget the session, stop watching, release the Cisco hold — also
    /// one a restarted service adopted.
    pub fn disarm(&self) {
        let mut s = self.state.lock().unwrap();
        self.disarm_locked(&mut s);
    }

    fn disarm_locked(&self, s: &mut State) {
        s.verified_login = None;
        self.stop_watch(s);
        self.guard.release(Some(CISCO_HOLDER), network_guard::reason::USER);
    }

    fn login_inputs(&self) -> Result<Inputs, String> {
        self.guard.held()
            .filter(|(holder, inputs)| holder == CISCO_HOLDER && inputs.login_port.is_some())
            .map(|(_, inputs)| inputs)
            .ok_or_else(|| "Cisco 登录的断线保护尚未就绪".into())
    }

    fn connected(self: &Arc<Self>, s: &mut State, tunnel: &str, gateways: &[String]) -> Result<(), String> {
        let current = self.login_inputs()?;
        if s.verified_login != Some(current.login_generation) {
            return Err("本次 Cisco 登录的断线保护尚未确认".into());
        }
        let [gateway] = gateways else { return Err("当前 Cisco 网关尚未确认".into()) };
        if !network_guard::is_ip(gateway) || !current.gateway_ips.contains(gateway) {
            return Err("当前 Cisco 网关不在本次连接的放行名单内".into());
        }
        if !tunnel.starts_with("utun") || !interface_exists(tunnel) {
            return Err("当前 Cisco 隧道尚未确认".into());
        }
        let mut inputs = current.clone();
        inputs.tunnel_if = tunnel.into();
        inputs.allow_dns = true;
        inputs.strict_dns = false;
        // Only the peer of the confirmed session is eligible for the next drop.
        inputs.gateway_ips = vec![gateway.clone()];
        if let Some(physical) = interface_toward(gateway) {
            inputs.physical_if = physical;
        }
        self.guard.apply_cisco_if_held(&current, true, &inputs)?;
        s.verified_login = None;
        network_guard::log("killswitch connected");
        self.start_watch(s, tunnel.into());
        Ok(())
    }

    fn block(&self, s: &mut State) -> Result<u64, String> {
        s.verified_login = None;
        let current = self.login_inputs()?;
        if !current.tunnel_if.is_empty() || self.guard.verify_login(CISCO_HOLDER).is_err() {
            let mut inputs = current.clone();
            inputs.tunnel_if.clear();
            inputs.allow_dns = false;
            inputs.local_dns_servers.clear();
            inputs.tunnel_dns_servers.clear();
            inputs.direct_table = false;
            inputs.strict_dns = true;
            inputs.block_direct = true;
            self.guard.apply_cisco_if_held(&current, false, &inputs)?;
            self.guard.verify_login(CISCO_HOLDER)?;
            network_guard::log("killswitch blocking");
        }
        self.stop_watch(s);
        Ok(current.login_generation)
    }

    /// While connected, block on our own the moment the tunnel interface
    /// disappears (Cisco tore the session down), App or not. The kernel
    /// announces it on the routing socket (§32.15: no 2 s polling); a check
    /// every 30 s remains as the fallback.
    fn start_watch(self: &Arc<Self>, s: &mut State, tunnel: String) {
        self.stop_watch(s);
        s.watch_generation += 1;
        let generation = s.watch_generation;
        s.watch = Some(generation);
        let read_end = match crate::child_io::pipe() {
            Ok((read,write)) => {s.watch_stop=Some(write);Some(read)},
            Err(_) => None,
        };
        let me = Arc::clone(self);
        let _ = std::thread::Builder::new().name("ac-killswitch".into()).stack_size(64 * 1024).spawn(move || {
            use std::os::fd::AsRawFd;
            let watch = crate::route_watch::RouteWatch::new();
            loop {
                match (&watch, &read_end) {
                    (Some(w), Some(stop)) => {
                        if let crate::route_watch::Wake::Stopped =
                            w.wait(Duration::from_secs(30), Duration::from_millis(50), Some(stop.as_raw_fd()))
                        {
                            return;
                        }
                    }
                    _ => {
                        let st = me.state.lock().unwrap();
                        drop(me.wake.wait_timeout(st, WATCH).unwrap());
                    }
                }
                let mut st = me.state.lock().unwrap();
                if st.watch != Some(generation) {
                    return;
                }
                if !interface_exists(&tunnel) {
                    network_guard::log("killswitch: Cisco tunnel gone, blocking");
                    let _ = me.block(&mut st);
                }
            }
        });
    }

    fn stop_watch(&self, s: &mut State) {
        s.watch = None;
        if let Some(stop) = s.watch_stop.take() {
            use std::os::fd::AsRawFd;
            unsafe { libc::write(stop.as_raw_fd(), [1u8].as_ptr() as *const libc::c_void, 1) };
        }
        self.wake.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    const GATEWAY: &str = "198.51.100.9";

    struct Firewall(PathBuf);

    impl Firewall {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
            let dir = std::env::temp_dir().join(format!("ac-cisco-{}-{}", std::process::id(), stamp.as_nanos()));
            std::fs::create_dir(&dir).unwrap();
            let stub = dir.join("pfctl");
            std::fs::write(&stub, r#"#!/bin/sh
dir=$(dirname "$0")
case "$*" in
    '-E') echo 'Token : 10' >&2 ;;
    '-a com.apple/300.AlwaysConnect -f -') cat > "$dir/rules" ;;
    '-a com.apple/300.AlwaysConnect -s rules') cat "$dir/rules" ;;
    '-a com.apple/300.AlwaysConnect -F rules')
        [ ! -e "$dir/refuse-release" ] || exit 1
        : > "$dir/rules" ;;
    '-a com.apple/300.AlwaysConnect -F Tables'|'-s states'|'-vv -s states'|'-X 10') ;;
    '-s rules') echo 'anchor "com.apple/300.AlwaysConnect" all' ;;
    '-s info') echo 'Status: Enabled' ;;
    *) exit 1 ;;
esac
"#).unwrap();
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(dir)
        }

        fn guard(&self) -> Arc<Guard> {
            Arc::new(Guard::new(network_guard::Settings {
                support_dir: self.0.clone(),
                boot: Some("fixture-boot".into()),
                grace: Duration::from_secs(120),
                pfctl: Some(self.0.join("pfctl").to_str().unwrap().into()),
            }))
        }

        fn read_rules(&self) -> String {
            std::fs::read_to_string(self.0.join("rules")).unwrap()
        }
    }

    impl Drop for Firewall {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn restored_cisco_hold_uses_strict_rules_and_can_be_released() {
        let fixture = Firewall::new();
        let guard = fixture.guard();
        guard.owner_attached();
        guard.supersede_own_holders();
        let mut login = Inputs::login("en99", vec![GATEWAY.into()], 8443, true);
        login.allow_networks = vec!["192.168.0.0/24".into()];
        guard.install_login(CISCO_HOLDER, &login).unwrap();
        let (_, armed) = guard.held().unwrap();
        let mut connected = armed.clone();
        connected.tunnel_if = "utun99".into();
        connected.allow_dns = true;
        connected.strict_dns = false;
        guard.apply_cisco_if_held(&armed, true, &connected).unwrap();

        let switch = Arc::new(KillSwitch::new(guard.clone()));
        assert!(switch.set(BLOCKING, "utun98", &["203.0.113.8".into()]).0);
        let rules = fixture.read_rules();
        assert!(rules.contains("proto { tcp udp } to 198.51.100.9 port 8443 no state"));
        assert!(rules.contains("block drop out quick proto { udp tcp } to any port 53"));
        assert!(!rules.contains("203.0.113.8"));
        assert!(!rules.contains("utun"));

        let (_, blocking) = guard.held().unwrap();
        guard.apply_cisco_if_held(&blocking, true, &connected).unwrap();
        let recovered = fixture.guard();
        recovered.adopt_at_start();
        recovered.owner_attached();
        let rules = fixture.read_rules();
        assert!(rules.contains("to 198.51.100.9 port 8443 no state"));
        assert!(!rules.contains("utun"));
        let switch = Arc::new(KillSwitch::new(recovered));
        assert!(!switch.is_off());
        assert!(switch.set(BLOCKING, "", &[]).0);
        std::fs::write(fixture.0.join("refuse-release"), "").unwrap();
        assert!(!switch.set(OFF, "", &[]).0);
        assert!(!switch.is_off());
        std::fs::remove_file(fixture.0.join("refuse-release")).unwrap();
        assert!(switch.set(OFF, "", &[]).0);
        assert!(switch.is_off());
        assert!(fixture.read_rules().is_empty());
        assert!(!switch.set(BLOCKING, "", &[]).0);
    }

    #[test]
    fn newly_armed_identical_login_rejects_old_handoff() {
        let fixture = Firewall::new();
        let guard = fixture.guard();
        guard.owner_attached();
        guard.supersede_own_holders();
        let login = Inputs::login("en99", vec![GATEWAY.into()], 443, true);
        guard.install_login(CISCO_HOLDER, &login).unwrap();
        let switch = Arc::new(KillSwitch::new(guard.clone()));
        assert!(switch.set(BLOCKING, "", &[]).0);
        let (_, old) = guard.held().unwrap();
        guard.supersede_own_holders();
        guard.install_login(CISCO_HOLDER, &login).unwrap();
        let (_, current) = guard.held().unwrap();
        assert_ne!(old.login_generation, current.login_generation);
        assert!(guard.apply_cisco_if_held(&old, false, &old).is_err());
        assert_eq!(switch.set(CONNECTED, "utun99", &[GATEWAY.into()]),
                   (false, "本次 Cisco 登录的断线保护尚未确认".into()));
        assert_eq!(guard.held().unwrap().1, current);
        switch.disarm();
    }
}
