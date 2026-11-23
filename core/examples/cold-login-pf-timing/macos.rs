use alwaysconnect_core::network_guard::{reason, Guard, LoginDeadlineStatus, Settings, ANCHOR};
use serde::Deserialize;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

const SUPPORT: &str = "/Library/Application Support/AlwaysConnect";
const PFCTL: &str = "/sbin/pfctl";
const CUTOFF_MS: u64 = 2_500;
const BUDGET_MS: u64 = 3_000;
const SAMPLE: Duration = Duration::from_millis(50);
const OBSERVE_MS: u64 = 3_650;
const MAX_COMMAND: Duration = Duration::from_millis(450);
type Result<T> = std::result::Result<T, &'static str>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    host: String,
    address: Ipv4Addr,
    path: String,
    uid: u32,
    gid: u32,
}

impl Config {
    fn valid(&self) -> bool {
        let [a, b, c, _] = self.address.octets();
        let public = !(self.address.is_private()
            || a == 0
            || a == 127
            || a >= 224
            || (a == 100 && (64..=127).contains(&b))
            || (a == 169 && b == 254)
            || (a == 192 && b == 0 && (c == 0 || c == 2))
            || (a == 192 && b == 88 && c == 99)
            || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
            || (a == 203 && b == 0 && c == 113));
        let valid_host = self.host.len() <= 253
            && self.host.contains('.')
            && self.host.bytes().any(|b| b.is_ascii_alphabetic())
            && self.host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        public
            && valid_host
            && self.uid >= 501
            && self.gid > 0
            && self.path.starts_with('/')
            && !self.path.starts_with("//")
            && self.path.len() <= 256
            && self
                .path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
    }
}

fn uptime() -> u64 {
    // Same sleep-excluding uptime used by DispatchTime and the Guard deadline.
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: libc initializes the output on success.
    unsafe {
        if libc::clock_gettime(libc::CLOCK_UPTIME_RAW, value.as_mut_ptr()) != 0 {
            return 0;
        }
        let value = value.assume_init();
        value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64
    }
}

fn ms(ns: u64) -> u64 {
    ns / 1_000_000
}

struct CommandOutput {
    success: bool,
    code: Option<i32>,
    out: String,
    err: String,
}

fn bounded_read(pipe: impl Read) -> std::io::Result<String> {
    let mut result = String::new();
    pipe.take(64 * 1024 + 1).read_to_string(&mut result)?;
    if result.len() > 64 * 1024 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(result)
}

fn command(program: &str, args: &[&str]) -> Result<CommandOutput> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "system_command_start_failed")?;
    let deadline = Instant::now() + MAX_COMMAND;
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    std::thread::scope(|scope| {
        let out = scope.spawn(move || bounded_read(out));
        let err = scope.spawn(move || bounded_read(err));
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("system_command_timeout");
                }
            }
        };
        Ok(CommandOutput {
            success: status.success(),
            code: status.code(),
            out: out.join().unwrap().map_err(|_| "system_command_output")?,
            err: err.join().unwrap().map_err(|_| "system_command_output")?,
        })
    })
}

fn pf(pfctl: &str, args: &[&str]) -> Result<String> {
    let result = command(pfctl, args)?;
    if !result.success
        || !result.err.lines().all(|line| {
            matches!(
                line.trim(),
                "" | "No ALTQ support in kernel" | "ALTQ related functions disabled"
            )
        })
    {
        return Err("pf_read_failed");
    }
    Ok(result.out)
}

fn anchor(pfctl: &str, field: &str) -> Result<String> {
    pf(pfctl, &["-a", ANCHOR, "-s", field])
}

fn anchor_empty(pfctl: &str) -> Result<()> {
    for field in ["rules", "Anchors", "Tables"] {
        if !anchor(pfctl, field)?.trim().is_empty() {
            return Err("product_anchor_not_empty");
        }
    }
    Ok(())
}

#[derive(PartialEq, Eq)]
struct PfBaseline {
    enabled: bool,
    references: Vec<String>,
}

fn pf_baseline(pfctl: &str) -> Result<PfBaseline> {
    let info = pf(pfctl, &["-s", "info"])?;
    let enabled = match info
        .lines()
        .find_map(|line| line.trim().strip_prefix("Status:"))
        .and_then(|status| status.split_whitespace().next())
    {
        Some("Enabled") => true,
        Some("Disabled") => false,
        _ => return Err("pf_status_unknown"),
    };
    let mut references: Vec<_> = pf(pfctl, &["-s", "References"])?
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty())
        .collect();
    references.sort_unstable();
    Ok(PfBaseline {
        enabled,
        references,
    })
}

fn route_interface(target: &str) -> Result<String> {
    let route = command("/sbin/route", &["-n", "get", "-inet", target])?;
    if !route.success {
        return Err("route_unconfirmed");
    }
    let name = route
        .out
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:"))
        .map(str::trim)
        .ok_or("route_interface_missing")?;
    match name.strip_prefix("en") {
        Some(suffix) if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) => {
            Ok(name.into())
        }
        _ => Err("route_not_physical"),
    }
}

fn absent(path: &Path) -> bool {
    matches!(fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

fn no_product_owner(support: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(support).map_err(|_| "product_support_unavailable")?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err("product_support_not_private");
    }
    for name in [
        "guard.json",
        "guard.json.tmp",
        "pf-state.json",
        "route-state",
        "direct-routes",
        "dns-state",
    ] {
        if !absent(&support.join(name)) {
            return Err("product_network_state_present");
        }
    }
    let label = "com.alwaysconnect.app.helper";
    let launch = command("/bin/launchctl", &["print", &format!("system/{label}")])?;
    if launch.success
        || !launch
            .err
            .contains(&format!("Could not find service \"{label}\""))
    {
        return Err("product_service_not_unloaded");
    }
    let process = command(
        "/usr/bin/pgrep",
        &[
            "-f",
            r"(^|/)(AlwaysConnect(Helper|-openconnect)?|com\.alwaysconnect\.app\.helper|alwaysconnect-gate|openconnect)([[:space:]]|$)",
        ],
    )?;
    if process.code != Some(1) || !process.out.is_empty() || !process.err.is_empty() {
        return Err("possible_product_process_or_vpn");
    }
    Ok(())
}

fn read_stage_file(stage: &Path, name: &str, read_only: bool) -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(stage.join(name))
        .map_err(|_| "watchdog_file_unavailable")?;
    let meta = file.metadata().map_err(|_| "watchdog_file_unavailable")?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.nlink() != 1
        || meta.mode() & 0o022 != 0
        || (read_only && meta.mode() & 0o777 != 0o400)
        || meta.len() > 4096
    {
        return Err("watchdog_file_unsafe");
    }
    let mut text = String::new();
    file.take(4097)
        .read_to_string(&mut text)
        .map_err(|_| "watchdog_file_unreadable")?;
    if text.len() > 4096 {
        return Err("watchdog_file_unsafe");
    }
    Ok(text)
}

struct Watchdog {
    stage: PathBuf,
    pid: i32,
}

impl Watchdog {
    fn check(&self, minimum_seconds: u64) -> Result<()> {
        for name in ["disarm", "guard-stopped", "rollback-reason"] {
            if !absent(&self.stage.join(name)) {
                return Err("watchdog_not_armed");
            }
        }
        if read_stage_file(&self.stage, "guard-ready", false)? != "ready\n" {
            return Err("watchdog_not_ready");
        }
        let connection = fs::symlink_metadata(self.stage.join("connection-good"))
            .map_err(|_| "watchdog_health_unavailable")?;
        if !connection.is_file()
            || connection.uid() != 0
            || connection.nlink() != 1
            || connection.mode() & 0o022 != 0
            || connection.len() != 0
            || !connection
                .modified()
                .ok()
                .and_then(|time| time.elapsed().ok())
                .is_some_and(|age| age <= Duration::from_secs(20))
        {
            return Err("watchdog_health_stale");
        }
        if read_stage_file(&self.stage, "exercise-done", false)? != "exercised\n" {
            return Err("watchdog_not_exercised");
        }
        let deadline: u64 = read_stage_file(&self.stage, "deadline", false)?
            .trim()
            .parse()
            .map_err(|_| "watchdog_deadline_invalid")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "wall_clock_unavailable")?
            .as_secs();
        // SAFETY: signal 0 checks process existence without sending a signal.
        if deadline.saturating_sub(now) < minimum_seconds || unsafe { libc::kill(self.pid, 0) } != 0
        {
            return Err("watchdog_expired");
        }
        Ok(())
    }

    fn find(stage: PathBuf) -> Result<Self> {
        let name = stage
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("invalid_stage")?;
        let suffix = name
            .strip_prefix("alwaysconnect-acceptance.")
            .ok_or("invalid_stage")?;
        if stage.parent() != Some(Path::new("/private/tmp"))
            || suffix.is_empty()
            || !suffix.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err("invalid_stage");
        }
        let meta = fs::symlink_metadata(&stage).map_err(|_| "invalid_stage")?;
        if !meta.is_dir() || meta.uid() != 0 || meta.gid() != 0 || meta.mode() & 0o777 != 0o700 {
            return Err("invalid_stage");
        }
        let label = format!("com.alwaysconnect.acceptance.{suffix}");
        if read_stage_file(&stage, "guard-label", false)?.trim() != label {
            return Err("watchdog_label_mismatch");
        }
        let pid: i32 = read_stage_file(&stage, "guard-pid", false)?
            .trim()
            .parse()
            .map_err(|_| "watchdog_pid_invalid")?;
        if pid <= 1 || pid as u32 == std::process::id() {
            return Err("watchdog_pid_invalid");
        }
        let result = command("/bin/launchctl", &["print", &format!("system/{label}")])?;
        if !result.success
            || !result
                .out
                .lines()
                .any(|line| line.trim() == format!("pid = {pid}"))
            || !result
                .out
                .lines()
                .any(|line| line.trim() == "state = running")
        {
            return Err("watchdog_launchd_mismatch");
        }
        let watchdog = Self { stage, pid };
        watchdog.check(60)?;
        Ok(watchdog)
    }

    fn register(&self) -> Result<()> {
        let pid = std::process::id() as i32;
        // SAFETY: create a process group containing this tool and its descendants only.
        if unsafe { libc::setpgid(0, 0) } != 0 && unsafe { libc::getpgrp() } != pid {
            return Err("process_group_unavailable");
        }
        self.write_marker("pf-timing-pgid", &format!("{pid}\n"))
    }

    fn write_marker(&self, name: &str, value: &str) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .mode(0o600)
            .create_new(true)
            .open(self.stage.join(name))
            .map_err(|_| "watchdog_marker_exists_or_unwritable")?;
        file.write_all(value.as_bytes())
            .map_err(|_| "watchdog_marker_write_failed")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EventKind {
    Ok,
    Timeout,
    Closed,
    Failed,
}

#[derive(Clone, Copy)]
struct Event {
    kind: EventKind,
    start: u64,
    end: u64,
}

impl Event {
    fn parse(line: &str) -> Option<Self> {
        let mut fields = line.split_whitespace();
        let kind = match fields.next()? {
            "ok" => EventKind::Ok,
            "timeout" => EventKind::Timeout,
            "closed" => EventKind::Closed,
            "failed" => EventKind::Failed,
            _ => return None,
        };
        let start = fields.next()?.parse().ok()?;
        let end = fields.next()?.parse().ok()?;
        (fields.next().is_none() && start <= end && end <= uptime()).then_some(Self {
            kind,
            start,
            end,
        })
    }
}

struct Probe {
    child: Child,
    events: mpsc::Receiver<Event>,
}

impl Probe {
    fn start(executable: &Path, config: &Config, count: u32) -> Result<Self> {
        let mut child = Command::new(executable)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "https_probe_start_failed")?;
        let stdout = child.stdout.take().unwrap();
        let input = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n",
            config.uid, config.gid, config.address, config.host, config.path, count
        );
        if child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .is_err()
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err("https_probe_input_failed");
        }
        let (send, events) = mpsc::channel();
        std::thread::spawn(move || {
            for row in BufReader::new(stdout.take(8 * 1024)).lines().take(65) {
                let Some(event) = row.ok().and_then(|line| Event::parse(&line)) else {
                    break;
                };
                if send.send(event).is_err() {
                    break;
                }
            }
        });
        Ok(Self { child, events })
    }

    fn successful_responses(&self, count: usize) -> Result<()> {
        let deadline = Instant::now() + Duration::from_millis(2_200);
        for _ in 0..count {
            if !matches!(
                self.events
                    .recv_timeout(deadline.saturating_duration_since(Instant::now())),
                Ok(Event {
                    kind: EventKind::Ok,
                    ..
                })
            ) {
                return Err("https_positive_control_failed");
            }
        }
        Ok(())
    }

    fn fresh_response(&self) -> Result<()> {
        let since = uptime();
        let deadline = Instant::now() + Duration::from_millis(600);
        loop {
            match self
                .events
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(Event {
                    kind: EventKind::Ok,
                    start,
                    ..
                }) if start >= since => return Ok(()),
                Ok(Event {
                    kind: EventKind::Ok,
                    ..
                }) => (),
                _ => return Err("https_pre_arm_control_failed"),
            }
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Measurements {
    start: u64,
    last_absent: u64,
    first_rule: Option<u64>,
    last_ok: Option<Event>,
    miss: Option<Event>,
}

impl Measurements {
    fn new(start: u64) -> Self {
        Self {
            start,
            last_absent: start,
            first_rule: None,
            last_ok: None,
            miss: None,
        }
    }

    fn rules(&mut self, started: u64, ended: u64, rules: &str) -> Result<()> {
        if rules.trim().is_empty() {
            if self.first_rule.is_some() {
                return Err("blocking_rule_disappeared");
            }
            self.last_absent = started;
        } else {
            if !rules
                .lines()
                .any(|line| line.trim() == "block drop out quick all")
            {
                return Err("unexpected_anchor_rules");
            }
            self.first_rule.get_or_insert(ended);
        }
        Ok(())
    }

    fn probe(&mut self, event: Event) {
        if event.kind == EventKind::Ok {
            self.last_ok = Some(event);
        } else if self.miss.is_none() {
            self.miss = Some(event);
        }
    }

    fn report(&self, status: LoginDeadlineStatus) -> Result<()> {
        let elapsed = |time: u64| ms(time.saturating_sub(self.start));
        println!("deadline_ms={CUTOFF_MS} guard_status={status:?}");
        if let Some(rule) = self.first_rule {
            println!(
                "pf_rule_seen_ms={} pf_rule_previous_empty_read_started_ms={}",
                elapsed(rule),
                elapsed(self.last_absent)
            );
        }
        if let (Some(ok), Some(miss)) = (self.last_ok, self.miss) {
            println!("https_last_response_started_ms={} https_last_response_ms={} https_first_miss_started_ms={} https_first_miss_seen_ms={} https_first_miss_kind={:?}",
                elapsed(ok.start), elapsed(ok.end), elapsed(miss.start), elapsed(miss.end), miss.kind);
        }
        if status != LoginDeadlineStatus::TimedOutBlocked {
            return Err("guard_did_not_confirm_timed_out_hold");
        }
        let Some(rule) = self.first_rule else {
            return Err("blocking_rule_not_seen");
        };
        let Some(ok) = self.last_ok else {
            return Err("https_pre_cutoff_response_missing");
        };
        let Some(miss) = self.miss else {
            return Err("https_miss_not_seen");
        };
        if rule < self.start + CUTOFF_MS * 1_000_000 || rule > self.start + BUDGET_MS * 1_000_000 {
            return Err("pf_read_outside_budget");
        }
        let cutoff = self.start + CUTOFF_MS * 1_000_000;
        if ok.end < cutoff - 300_000_000
            || miss.start < cutoff - 150_000_000
            || miss.end < cutoff
            || miss.end < self.last_absent
            || ok.start >= rule
            || miss.start > self.start + BUDGET_MS * 1_000_000
            || miss.end > self.start + OBSERVE_MS * 1_000_000
            || !matches!(miss.kind, EventKind::Closed | EventKind::Timeout)
            || ok.end > miss.start
        {
            return Err("https_cutoff_inconclusive");
        }
        Ok(())
    }
}

fn observe(
    pfctl: &str,
    events: &mpsc::Receiver<Event>,
    result: &mut Measurements,
    mut check_watchdog: impl FnMut() -> Result<()>,
) -> Result<()> {
    let stop = result.start + OBSERVE_MS * 1_000_000;
    let mut next = uptime();
    while uptime() < stop {
        if uptime() < next {
            match events.recv_timeout(Duration::from_nanos(next.saturating_sub(uptime()))) {
                Ok(event) => result.probe(event),
                Err(mpsc::RecvTimeoutError::Timeout) => (),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    if result.miss.is_none() {
                        return Err("https_probe_ended_without_result");
                    }
                    std::thread::sleep(Duration::from_nanos(next.saturating_sub(uptime())));
                }
            }
            continue;
        }
        // A stopped rollback or a competing operator ends the measurement immediately.
        check_watchdog()?;
        let start = uptime();
        let rules = anchor(pfctl, "rules")?;
        result.rules(start, uptime(), &rules)?;
        if result.first_rule.is_some() && result.miss.is_some() {
            return Ok(());
        }
        next = start + SAMPLE.as_nanos() as u64;
    }
    Ok(())
}

fn verify_restored(pfctl: &str, settings: &Path, baseline: &PfBaseline) -> Result<()> {
    anchor_empty(pfctl)?;
    if !absent(&settings.join("guard.json"))
        || !absent(&settings.join("guard.json.tmp"))
        || &pf_baseline(pfctl)? != baseline
    {
        return Err("pf_restore_unconfirmed");
    }
    Ok(())
}

fn stop_guard(guard: &Arc<Guard>, holder: &str, ticket: u64) -> Result<LoginDeadlineStatus> {
    let status = guard.login_deadline_status(ticket);
    // No preparation result is delivered. Cancel first so no retry can
    // reload the anchor after the holder's normal release.
    guard.cancel_login_deadline(ticket);
    guard.release(Some(holder), reason::USER);
    if guard.is_holding() || guard.has_pending_login_deadline() {
        return Err("guard_release_unconfirmed");
    }
    Ok(status)
}

fn run(watchdog: &Watchdog) -> Result<()> {
    let support = Path::new(SUPPORT);
    let bin = watchdog.stage.join("tools.app/Contents/Resources");
    if std::env::current_exe().ok().as_deref() != Some(&bin.join("pf-timing")) {
        return Err("expected_verified_stage_executable");
    }
    let config: Config =
        serde_json::from_str(&read_stage_file(&watchdog.stage, "pf-timing.json", true)?)
            .map_err(|_| "invalid_probe_configuration")?;
    if !config.valid() {
        return Err("invalid_probe_configuration");
    }
    let boot = command("/usr/sbin/sysctl", &["-n", "kern.bootsessionuuid"])?;
    let boot_id = boot.out.trim();
    if !boot.success || boot_id.is_empty() {
        return Err("boot_id_unknown");
    }
    let target = config.address.to_string();
    let physical = route_interface("default")?;
    if route_interface(&target)? != physical {
        return Err("target_route_not_default_physical");
    }
    no_product_owner(support)?;
    anchor_empty(PFCTL)?;
    let baseline = pf_baseline(PFCTL)?;
    let probe_bin = bin.join("pf-timing-https");
    let probe = Probe::start(&probe_bin, &config, 64)?;
    probe.successful_responses(3)?;
    watchdog.check(11)?;
    no_product_owner(support)?;
    if route_interface("default")? != physical || route_interface(&target)? != physical {
        return Err("route_changed");
    }
    anchor_empty(PFCTL)?;
    if pf_baseline(PFCTL)? != baseline {
        return Err("pf_baseline_changed");
    }
    probe.fresh_response()?;
    watchdog.check(10)?;
    let guard = Arc::new(Guard::new(Settings {
        support_dir: support.to_path_buf(),
        boot: Some(boot_id.into()),
        grace: Duration::from_secs(120),
        pfctl: Some(PFCTL.into()),
    }));
    guard.owner_attached();
    let holder = guard.new_own_holder();
    // A refusal before this marker has no PF side effects. After it the
    // independent watchdog must assume the deadline could be armed.
    watchdog.write_marker("pf-timing-armed", &format!("{holder}\n"))?;
    let start = uptime();
    if start == 0 {
        return Err("uptime_unavailable");
    }
    let ticket = guard.arm_login_deadline(
        &holder,
        &physical,
        443,
        false,
        start + CUTOFF_MS * 1_000_000,
    );
    if ticket == 0 {
        fs::remove_file(watchdog.stage.join("pf-timing-armed"))
            .map_err(|_| "guard_refusal_marker_not_cleared")?;
        return Err("guard_refused_deadline");
    }
    let mut result = Measurements::new(start);
    let observation = observe(PFCTL, &probe.events, &mut result, || watchdog.check(2));
    drop(probe);
    let status = stop_guard(&guard, &holder, ticket)?;
    verify_restored(PFCTL, support, &baseline)?;
    if route_interface("default")? != physical || route_interface(&target)? != physical {
        return Err("route_restore_unconfirmed");
    }
    Probe::start(&probe_bin, &config, 1)?.successful_responses(1)?;
    watchdog.write_marker("pf-timing-clean", "restored\n")?;
    println!("restored=true");
    let assessment = result.report(status);
    observation.and(assessment)
}

pub fn main() -> ExitCode {
    let result = (|| {
        // SAFETY: these functions only read this process's credentials.
        if unsafe { libc::getuid() } != 0 || unsafe { libc::geteuid() } != 0 {
            return Err("requires_existing_root_watchdog");
        }
        let mut args = std::env::args_os().skip(1);
        let stage = args
            .next()
            .map(PathBuf::from)
            .ok_or("expected_one_stage_argument")?;
        if args.next().is_some() {
            return Err("expected_one_stage_argument");
        }
        // SAFETY: affects only this process and its children.
        unsafe {
            libc::umask(0o077);
        }
        let watchdog = Watchdog::find(stage)?;
        watchdog.register()?;
        run(&watchdog)
    })();
    match result {
        Ok(()) => {
            println!("result=pass");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            println!("result=fail reason={reason}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
