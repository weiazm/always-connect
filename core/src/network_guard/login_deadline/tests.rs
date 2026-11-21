use super::*;
use crate::network_guard::{reason, Settings};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

const GATEWAY: &str = "198.51.100.7";
const CUTOFF: Duration = Duration::from_secs(1);

struct Fixture {
    dir: PathBuf,
    guard: Arc<Guard>,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ac-login-deadline-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&dir).unwrap();
        for file in ["rules", "children", "states"] {
            fs::write(dir.join(file), "").unwrap();
        }
        let tool = dir.join("pfctl");
        fs::write(&tool, r#"#!/bin/sh
D=${0%/*}
printf '%s\n' "$*" >> "$D/calls"
case "$*" in
    '-E') [ ! -f "$D/reject-enable" ] || exit 1; echo 'Token : 10' >&2 ;;
    '-a com.apple/300.AlwaysConnect -f -')
        if [ -f "$D/stall-load" ]; then exec /bin/sleep 20; fi
        if [ -f "$D/reject-next-load" ]; then rm "$D/reject-next-load"; exit 1; fi
        cat > "$D/rules"
        if /usr/bin/grep -q '198.51.100.7' "$D/rules"; then
            echo carrier >> "$D/calls"
        else
            echo empty >> "$D/calls"
        fi ;;
    '-a com.apple/300.AlwaysConnect -s rules')
        if [ -f "$D/unreadable" ]; then echo 'unexpected pf error' >&2; exit 0; fi
        if [ -f "$D/reject-carrier-readback" ] && /usr/bin/grep -q '198.51.100.7' "$D/rules"; then exit 1; fi
        cat "$D/rules" ;;
    '-a com.apple/300.AlwaysConnect -s Anchors') cat "$D/children" ;;
    '-a com.apple/300.AlwaysConnect -F rules') : > "$D/rules" ;;
    '-a com.apple/300.AlwaysConnect -F Tables'|'-X 10') ;;
    '-s rules') echo 'anchor "com.apple/300.AlwaysConnect" all' ;;
    '-s info') echo 'Status: Enabled' ;;
    '-vv -s states') cat "$D/states" ;;
    '-i en0 -k 192.0.2.2 -k 203.0.113.7')
        : > "$D/states"; echo 'killed 1 states from 1 sources and 1 destinations' >&2 ;;
    *) exit 1 ;;
esac
"#).unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        let guard = Arc::new(Guard::new(Settings {
            support_dir: dir.clone(),
            boot: Some("fixture-boot".into()),
            grace: Duration::from_secs(120),
            pfctl: Some(tool.into_os_string().into_string().unwrap()),
        }));
        guard.owner_attached();
        Self { dir, guard }
    }

    fn write(&self, name: &str, value: &str) {
        fs::write(self.dir.join(name), value).unwrap();
    }
    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.dir.join(name)).unwrap()
    }

    fn arm(&self, holder: &str, window: Duration) -> u64 {
        self.guard.arm_login_deadline(
            holder,
            "en0",
            443,
            holder == CISCO_HOLDER,
            uptime_ns().unwrap() + u64::try_from(window.as_nanos()).unwrap(),
        )
    }

    fn finish(&self, token: u64) -> Result<(), String> {
        self.guard
            .finish_login_deadline(token, vec![GATEWAY.into()])
    }

    fn until(&self, check: impl Fn() -> bool) {
        let limit = Instant::now() + Duration::from_secs(6);
        while !check() {
            assert!(
                Instant::now() < limit,
                "pfctl calls: {}",
                self.read("calls")
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn assert_empty_block(&self) {
        let rules = self.read("rules");
        assert!(rules.ends_with("block drop out quick all\n"));
        assert!(!rules.contains(GATEWAY));
        let (_, inputs) = self.guard.held().unwrap();
        assert!(inputs.gateway_ips.is_empty());
        assert!(inputs.tunnel_if.is_empty());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.guard.release(None, reason::USER);
        fs::remove_dir_all(&self.dir).unwrap();
    }
}

fn state_row(interface: &str) -> String {
    format!(
        "{interface} tcp 192.0.2.2:54000 -> 203.0.113.7:443 ESTABLISHED:ESTABLISHED\n\
          age 00:00:01, expires in 00:02:00, 0:0 pkts, 0:0 bytes, rule 8\n\
          id: 0000000000000001 creatorid: 00000001\n"
    )
}

#[test]
fn finish_blocks_and_clears_old_state_before_admitting_the_candidate() {
    let fixture = Fixture::new();
    fixture.write("states", &state_row("en0"));
    let holder = fixture.guard.new_own_holder();
    let token = fixture.arm(&holder, Duration::from_secs(3));
    assert_ne!(token, 0);
    assert_eq!(
        fixture.guard.login_deadline_status(token),
        LoginDeadlineStatus::Pending
    );
    assert!(!fixture.guard.is_holding());
    assert_eq!(fixture.finish(token), Ok(()));
    assert_eq!(
        fixture.guard.login_deadline_status(token),
        LoginDeadlineStatus::Finished
    );
    let calls = fixture.read("calls");
    assert!(calls.find("empty\n").unwrap() < calls.find("-i en0 -k").unwrap());
    assert!(calls.find("-i en0 -k").unwrap() < calls.find("carrier\n").unwrap());
    assert!(fixture
        .read("rules")
        .contains(&format!("proto tcp to {GATEWAY} port 443 no state")));
    assert!(fixture.finish(token).is_err());
}

#[test]
fn deadline_blocks_without_the_app_and_late_candidates_cannot_widen_it() {
    let fixture = Fixture::new();
    let token = fixture.arm(CISCO_HOLDER, CUTOFF);
    assert_ne!(token, 0);
    fixture.guard.owner_lost(false);
    fixture.until(|| {
        fixture.guard.login_deadline_status(token) == LoginDeadlineStatus::TimedOutBlocked
    });
    assert!(fixture.guard.state.lock().unwrap().grace.is_some());
    fixture.assert_empty_block();
    assert_eq!(fixture.finish(token), Err(TIMEOUT.into()));
    assert!(!fixture.read("calls").contains("carrier\n"));
}

#[test]
fn failed_preparation_completes_with_verified_empty_rules() {
    let fixture = Fixture::new();
    let token = fixture.arm(CISCO_HOLDER, Duration::from_secs(3));
    assert_ne!(token, 0);
    assert_eq!(
        fixture.guard.finish_login_deadline(token, Vec::new()),
        Ok(())
    );
    fixture.assert_empty_block();
}

#[test]
fn loaded_rules_with_ambiguous_old_state_never_report_confirmed() {
    let fixture = Fixture::new();
    fixture.write("states", &state_row("all"));
    let token = fixture.arm(CISCO_HOLDER, CUTOFF);
    assert_ne!(token, 0);
    fixture.until(|| !fixture.guard.has_pending_login_deadline());
    fixture.assert_empty_block();
    assert_eq!(
        fixture.guard.login_deadline_status(token),
        LoginDeadlineStatus::ProtectionUnconfirmed
    );
    assert!(fixture
        .guard
        .login_deadline_error(token)
        .unwrap()
        .contains("已有连接的拦截未确认"));
    assert!(fixture.finish(token).is_err());
    assert_eq!(fixture.read("calls").matches("empty\n").count(), 3);
}

#[test]
fn rule_install_timeout_is_bounded_and_a_later_recovery_can_rearm() {
    let fixture = Fixture::new();
    fixture.write("stall-load", "");
    let token = fixture.arm(CISCO_HOLDER, CUTOFF);
    assert_ne!(token, 0);
    fixture.until(|| !fixture.guard.has_pending_login_deadline());
    assert_eq!(
        fixture.guard.login_deadline_status(token),
        LoginDeadlineStatus::ProtectionUnconfirmed
    );
    assert!(!fixture.guard.is_holding());
    assert!(fixture.finish(token).is_err());
    assert_eq!(fixture.read("calls").matches("-f -\n").count(), 3);
    assert_eq!(fixture.arm(CISCO_HOLDER, Duration::from_secs(3)), 0);
    fixture.guard.release(None, reason::USER);
    fs::remove_file(fixture.dir.join("stall-load")).unwrap();
    assert_ne!(fixture.arm(CISCO_HOLDER, Duration::from_secs(3)), 0);
}

#[test]
fn failed_load_can_retry_but_never_reopens_preparation() {
    let fixture = Fixture::new();
    fixture.write("reject-next-load", "");
    let token = fixture.arm(CISCO_HOLDER, CUTOFF);
    assert_ne!(token, 0);
    fixture.until(|| {
        fixture.guard.login_deadline_status(token) == LoginDeadlineStatus::TimedOutBlocked
    });
    fixture.assert_empty_block();
    assert_eq!(fixture.read("calls").matches("-f -\n").count(), 2);
}

#[test]
fn candidate_readback_failure_restores_the_verified_empty_block() {
    let fixture = Fixture::new();
    fixture.write("reject-carrier-readback", "");
    let token = fixture.arm(CISCO_HOLDER, Duration::from_secs(3));
    assert_ne!(token, 0);
    assert!(fixture.finish(token).unwrap_err().contains("规则未确认"));
    fixture.assert_empty_block();
    let calls: Vec<_> = fixture
        .read("calls")
        .lines()
        .filter(|line| matches!(*line, "empty" | "carrier"))
        .map(str::to_owned)
        .collect();
    assert_eq!(calls, ["empty", "carrier", "empty"]);
}

#[test]
fn only_a_current_direct_generation_can_arm() {
    let fixture = Fixture::new();
    assert_eq!(fixture.arm(CISCO_HOLDER, Duration::from_secs(4)), 0);
    assert_eq!(fixture.arm(CISCO_HOLDER, Duration::ZERO), 0);
    assert_eq!(fixture.arm("own:0", CUTOFF), 0);
    fixture.write("rules", "block drop out quick all\n");
    assert_eq!(fixture.arm(CISCO_HOLDER, CUTOFF), 0);
    fixture.write("rules", "");
    fixture.write("children", "com.apple/300.AlwaysConnect/old\n");
    assert_eq!(fixture.arm(CISCO_HOLDER, CUTOFF), 0);
    fixture.write("children", "");
    fixture.write("unreadable", "");
    assert_eq!(fixture.arm(CISCO_HOLDER, CUTOFF), 0);
    fs::remove_file(fixture.dir.join("unreadable")).unwrap();
    fixture.write("guard.json", "corrupt record");
    assert_eq!(fixture.arm(CISCO_HOLDER, CUTOFF), 0);
    fs::remove_file(fixture.dir.join("guard.json")).unwrap();
    let holder = fixture.guard.new_own_holder();
    fixture.guard.own_engine_started(&holder);
    assert_eq!(fixture.arm(CISCO_HOLDER, CUTOFF), 0);
    fixture.guard.own_engine_finished(&holder);
    assert_ne!(fixture.arm(&holder, Duration::from_secs(3)), 0);
    assert_eq!(fixture.arm(CISCO_HOLDER, CUTOFF), 0);
}

#[test]
fn restore_cancel_and_supersede_retire_only_the_matching_deadline() {
    let fixture = Fixture::new();
    let first = fixture.arm(CISCO_HOLDER, CUTOFF);
    assert_ne!(first, 0);
    fixture.guard.supersede_own_holders();
    let holder = fixture.guard.new_own_holder();
    let next = fixture.arm(&holder, CUTOFF);
    assert_ne!(next, 0);
    assert_ne!(next, first);
    fixture.guard.cancel_login_deadline(first);
    fixture.guard.release(Some(CISCO_HOLDER), reason::USER);
    assert_eq!(
        fixture.guard.login_deadline_status(next),
        LoginDeadlineStatus::Pending
    );
    fixture.guard.cancel_login_deadline(next);
    let last = fixture.arm(CISCO_HOLDER, CUTOFF);
    assert_ne!(last, 0);
    fixture.guard.release(None, reason::USER);
    let until = Instant::now() + CUTOFF;
    for token in [first, next, last] {
        assert_eq!(
            fixture.guard.login_deadline_status(token),
            LoginDeadlineStatus::Stale
        );
        assert!(fixture.finish(token).is_err());
    }
    std::thread::sleep(until.saturating_duration_since(Instant::now()));
    assert_eq!(fixture.read("rules"), "");
    assert!(!fixture.read("calls").contains("-f -\n"));
}
