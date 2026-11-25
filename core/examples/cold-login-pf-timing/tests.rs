use super::*;
use std::ffi::{CStr, CString};
use std::os::unix::fs::PermissionsExt;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let template = CString::new(
            std::env::temp_dir()
                .join("ac-pf-timing.XXXXXX")
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let mut template = template.into_bytes_with_nul();
        // SAFETY: mkdtemp owns the writable NUL-terminated template during this call.
        let directory = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
        assert!(!directory.is_null());
        // SAFETY: the successful call returned the same NUL-terminated buffer.
        Self(PathBuf::from(
            unsafe { CStr::from_ptr(directory) }.to_str().unwrap(),
        ))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn runs_the_production_guard_through_the_fake_pf_and_restoration() {
    let scratch = Scratch::new();
    let tool = scratch.0.join("pfctl");
    fs::write(&tool, include_str!("../../scripts/fake-pfctl.sh")).unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
    let rules = scratch.0.join("current.rules");
    fs::write(&rules, "").unwrap();
    let pfctl = tool.to_str().unwrap();
    let support = scratch.0.join("support");
    fs::create_dir(&support).unwrap();
    let baseline = pf_baseline(pfctl).unwrap();
    anchor_empty(pfctl).unwrap();

    let guard = Arc::new(Guard::new(Settings {
        support_dir: support.clone(),
        boot: Some("test-boot".into()),
        grace: Duration::from_secs(120),
        pfctl: Some(pfctl.into()),
    }));
    guard.owner_attached();
    let holder = guard.new_own_holder();
    let start = uptime();
    let ticket = guard.arm_login_deadline(&holder, "en0", 443, false, start + 2_500_000_000);
    assert_ne!(ticket, 0);
    assert!(anchor(pfctl, "rules").unwrap().is_empty());

    // The scripted HTTPS response sequence uses the same clock. No DNS,
    // connection or system pfctl is used by this test.
    let (send, events) = mpsc::channel();
    let sender = std::thread::spawn(move || {
        let until = start + 2_450_000_000;
        std::thread::sleep(Duration::from_nanos(until.saturating_sub(uptime())));
        send.send(Event {
            kind: EventKind::Ok,
            start: until - 70_000_000,
            end: until,
        })
        .unwrap();
        let bound = Instant::now() + Duration::from_millis(700);
        while fs::read_to_string(&rules).unwrap().trim().is_empty() {
            assert!(Instant::now() < bound, "fake pf never applied the block");
            std::thread::sleep(Duration::from_millis(5));
        }
        let miss = uptime();
        std::thread::sleep(Duration::from_millis(350));
        send.send(Event {
            kind: EventKind::Timeout,
            start: miss,
            end: uptime(),
        })
        .unwrap();
    });
    let mut measurements = Measurements::new(start);
    let observation = observe(pfctl, &events, &mut measurements, || Ok(()));
    let status = stop_guard(&guard, &holder, ticket).unwrap();
    sender.join().unwrap();
    observation.unwrap();
    measurements.report(status).unwrap();
    verify_restored(pfctl, &support, &baseline).unwrap();

    let calls = fs::read_to_string(scratch.0.join("pfctl.log")).unwrap();
    assert_eq!(calls.lines().filter(|line| *line == "-E").count(), 1);
    assert_eq!(calls.lines().filter(|line| *line == "-X 10001").count(), 1);
    assert!(!calls
        .lines()
        .any(|line| line == "-d" || line.ends_with("-F all")));
}

#[test]
fn rejects_early_closure_and_responses_to_requests_started_after_rule_readback() {
    let start = 5_000_000_000;
    let rule = start + 2_550_000_000;
    let mut measurements = Measurements::new(start);
    measurements
        .rules(start + 2_500_000_000, rule, "block drop out quick all")
        .unwrap();
    measurements.probe(Event {
        kind: EventKind::Ok,
        start: start + 2_300_000_000,
        end: start + 2_350_000_000,
    });
    measurements.probe(Event {
        kind: EventKind::Closed,
        start: start + 2_360_000_000,
        end: start + 2_400_000_000,
    });
    assert_eq!(
        measurements.report(LoginDeadlineStatus::TimedOutBlocked),
        Err("https_cutoff_inconclusive")
    );

    measurements.miss = None;
    measurements.probe(Event {
        kind: EventKind::Ok,
        start: rule + 20_000_000,
        end: rule + 40_000_000,
    });
    measurements.probe(Event {
        kind: EventKind::Timeout,
        start: rule + 140_000_000,
        end: rule + 490_000_000,
    });
    assert_eq!(
        measurements.report(LoginDeadlineStatus::TimedOutBlocked),
        Err("https_cutoff_inconclusive")
    );
}

#[test]
fn rejects_late_or_unconfirmed_pf_and_unapproved_probe_shapes() {
    let mut measurements = Measurements::new(0);
    assert!(measurements
        .rules(2_500_000_000, 2_550_000_000, "pass quick all")
        .is_err());
    measurements
        .rules(3_000_000_000, 3_010_000_000, "block drop out quick all")
        .unwrap();
    measurements.probe(Event {
        kind: EventKind::Ok,
        start: 2_300_000_000,
        end: 2_350_000_000,
    });
    measurements.probe(Event {
        kind: EventKind::Timeout,
        start: 2_650_000_000,
        end: 3_000_000_000,
    });
    assert_eq!(
        measurements.report(LoginDeadlineStatus::ProtectionUnconfirmed),
        Err("guard_did_not_confirm_timed_out_hold")
    );
    assert_eq!(
        measurements.report(LoginDeadlineStatus::TimedOutBlocked),
        Err("pf_read_outside_budget")
    );
    assert!(Event::parse("ok 30 20").is_none());
    assert!(Event::parse("unknown 20 30").is_none());

    let config = |address, host: &str, path: &str| Config {
        address,
        host: host.into(),
        path: path.into(),
        uid: 501,
        gid: 20,
    };
    assert!(!config(Ipv4Addr::LOCALHOST, "example.test", "/check").valid());
    // Validation only. No request is made to these values.
    let ip = Ipv4Addr::new(1, 2, 3, 4);
    assert!(config(ip, "example.test", "/check").valid());
    assert!(!config(ip, "example.test", "/check?secret=1").valid());
    assert!(!config(ip, "example.test\r\nHost: bad", "/check").valid());
}
