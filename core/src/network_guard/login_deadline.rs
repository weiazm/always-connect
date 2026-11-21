//! A short, one-use authorization to finish cold gateway preparation while
//! direct. The worker and the caller both commit through the guard lock.

use super::{log, text, Guard, Inputs, State, ANCHOR, CISCO_HOLDER};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests;

const MAX_PREPARATION_NS: u64 = 3_000_000_000;
const PF_LOAD_LIMIT: Duration = Duration::from_millis(750);
const PF_VERIFY_LIMIT: Duration = Duration::from_secs(2);
const RETRY_DELAY: Duration = Duration::from_millis(125);
const MAX_RETRIES: u8 = 2;
const STALE: &str = "连接请求已过期";
const LOAD_FAILED: &str = "登录保护规则未能装载";
const TIMEOUT: &str = "查找 VPN 网关超时，网络已拦截";

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginDeadlineStatus {
    Stale = 0,
    Pending = 1,
    TimedOutBlocked = 2,
    ProtectionUnconfirmed = 3,
    Finished = 4,
}

pub(super) struct LoginDeadline {
    token: u64,
    pub(super) holder: String,
    empty: Inputs,
    cutoff: u64,
    progress: Progress,
}

enum Progress {
    Waiting,
    Retrying {
        at: Instant,
        remaining: u8,
        outcome: Blocked,
        error: String,
    },
    Done(LoginDeadlineStatus, Option<String>),
}

enum Blocked {
    Timeout,
    Rejected(String),
}

// DispatchTime.uptimeNanoseconds uses Mach absolute time on macOS, the
// same uptime clock as CLOCK_UPTIME_RAW. Neither advances through sleep.
fn uptime_ns() -> Option<u64> {
    #[cfg(target_os = "macos")]
    let clock = libc::CLOCK_UPTIME_RAW;
    #[cfg(not(target_os = "macos"))]
    let clock = libc::CLOCK_MONOTONIC;
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(clock, &mut value) } != 0 {
        return None;
    }
    u64::try_from(value.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(value.tv_nsec).ok()?)
}

impl LoginDeadline {
    fn time_left(&self) -> Duration {
        Duration::from_nanos(self.cutoff.saturating_sub(uptime_ns().unwrap_or(u64::MAX)))
    }
}

impl Guard {
    pub fn arm_login_deadline(
        self: &Arc<Self>,
        holder: &str,
        physical: &str,
        port: u16,
        cisco: bool,
        cutoff: u64,
    ) -> u64 {
        let mut state = self.state.lock().unwrap();
        let Some(now) = uptime_ns() else { return 0 };
        let remaining = cutoff.saturating_sub(now);
        let valid_holder = if cisco {
            holder == CISCO_HOLDER
        } else {
            state.own_generation != 0 && holder == format!("own:{}", state.own_generation)
        };
        if remaining == 0
            || remaining > MAX_PREPARATION_NS
            || !valid_holder
            || physical.is_empty()
            || state.record.is_some()
            || state.active_own.is_some()
            || state.pf.token.is_some()
            || state.login_deadline.is_some()
            || state.login_deadline_needs_recovery
            || !self.no_saved_hold()
        {
            return 0;
        }
        let mut empty = Inputs::login(physical, Vec::new(), port, cisco);
        empty.login_generation = state.own_generation;
        if text(false, &empty).is_none()
            || crate::pf_verify::BlockingPolicy::new(
                physical,
                &[],
                port,
                cisco,
                &empty.allow_networks,
            )
            .is_err()
        {
            return 0;
        }
        let read_limit = Instant::now() + Duration::from_nanos(remaining).min(PF_LOAD_LIMIT);
        for field in ["rules", "Anchors"] {
            if !state
                .pf
                .audit(&["-a", ANCHOR, "-s", field], read_limit)
                .is_ok_and(|out| {
                    out.stdout.trim().is_empty()
                        && out.stderr.lines().all(|line| {
                            matches!(
                                line.trim(),
                                "" | "No ALTQ support in kernel"
                                    | "ALTQ related functions disabled"
                            )
                        })
                })
            {
                return 0;
            }
        }
        if uptime_ns().is_none_or(|now| now >= cutoff) {
            return 0;
        }

        state.deadline_generation = state.deadline_generation.wrapping_add(1).max(1);
        let token = state.deadline_generation;
        state.login_deadline = Some(LoginDeadline {
            token,
            holder: holder.into(),
            empty,
            cutoff,
            progress: Progress::Waiting,
        });
        let guard = Arc::clone(self);
        if std::thread::Builder::new()
            .name("ac-login-deadline".into())
            .spawn(move || {
                guard.wait_for_login_deadline(token);
            })
            .is_err()
        {
            self.clear_login_deadline(&mut state);
            return 0;
        }
        token
    }

    fn no_saved_hold(&self) -> bool {
        std::fs::symlink_metadata(self.record_path())
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    }

    pub fn finish_login_deadline(
        self: &Arc<Self>,
        token: u64,
        gateways: Vec<String>,
    ) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        let task = state
            .login_deadline
            .as_ref()
            .filter(|task| task.token == token)
            .ok_or(STALE)?;
        if !matches!(task.progress, Progress::Waiting) {
            return Err(Self::deadline_error(task).unwrap_or_else(|| STALE.into()));
        }
        let mut task = state.login_deadline.take().unwrap();
        if task.time_left().is_zero() {
            self.block_for_deadline(&mut state, &mut task, Blocked::Timeout, MAX_RETRIES);
        } else {
            self.finish_login_locked(&mut state, &mut task, gateways);
        }
        let result = Self::deadline_error(&task).map_or(Ok(()), Err);
        state.login_deadline = Some(task);
        self.login_wake.notify_all();
        result
    }

    fn finish_login_locked(
        self: &Arc<Self>,
        state: &mut State,
        task: &mut LoginDeadline,
        gateways: Vec<String>,
    ) {
        if let Err(error) = self.apply_deadline_rules(state, &task.holder, &task.empty) {
            self.retry_block(
                task,
                Blocked::Rejected("登录已暂停".into()),
                MAX_RETRIES,
                error,
            );
            return;
        }
        if !gateways.is_empty() {
            if task.time_left().is_zero() {
                task.progress =
                    Progress::Done(LoginDeadlineStatus::TimedOutBlocked, Some(TIMEOUT.into()));
                return;
            }
            let mut prepared = task.empty.clone();
            prepared.gateway_ips = gateways;
            if let Err(error) = self.apply_deadline_rules(state, &task.holder, &prepared) {
                self.block_for_deadline(state, task, Blocked::Rejected(error), MAX_RETRIES);
                return;
            }
        }
        task.progress = Progress::Done(LoginDeadlineStatus::Finished, None);
    }

    fn apply_deadline_rules(
        self: &Arc<Self>,
        state: &mut State,
        holder: &str,
        inputs: &Inputs,
    ) -> Result<(), String> {
        state.login_deadline_needs_recovery = true;
        let rules = text(false, inputs).ok_or("登录保护规则无效")?;
        state
            .pf
            .load_before(&rules, Instant::now() + PF_LOAD_LIMIT)
            .map_err(|()| LOAD_FAILED)?;
        self.record_applied(state, holder, false, inputs);
        self.verify_login_locked(state, holder, Instant::now() + PF_VERIFY_LIMIT)
    }

    fn block_for_deadline(
        self: &Arc<Self>,
        state: &mut State,
        task: &mut LoginDeadline,
        outcome: Blocked,
        remaining: u8,
    ) {
        match self.apply_deadline_rules(state, &task.holder, &task.empty) {
            Ok(()) => {
                let (status, message) = match outcome {
                    Blocked::Timeout => (LoginDeadlineStatus::TimedOutBlocked, TIMEOUT.into()),
                    Blocked::Rejected(error) => (LoginDeadlineStatus::Finished, error),
                };
                task.progress = Progress::Done(status, Some(message));
            }
            Err(error) => self.retry_block(task, outcome, remaining, error),
        }
    }

    fn retry_block(
        &self,
        task: &mut LoginDeadline,
        outcome: Blocked,
        remaining: u8,
        error: String,
    ) {
        let error = format!("登录已暂停，保护未确认：{error}");
        log(&error);
        task.progress = if remaining == 0 {
            Progress::Done(LoginDeadlineStatus::ProtectionUnconfirmed, Some(error))
        } else {
            Progress::Retrying {
                at: Instant::now() + RETRY_DELAY,
                remaining,
                outcome,
                error,
            }
        };
    }

    fn wait_for_login_deadline(self: &Arc<Self>, token: u64) {
        let mut state = self.state.lock().unwrap();
        loop {
            let Some(task) = state
                .login_deadline
                .as_ref()
                .filter(|task| task.token == token)
            else {
                return;
            };
            let time_left = match &task.progress {
                Progress::Waiting => task.time_left(),
                Progress::Retrying { at, .. } => at.saturating_duration_since(Instant::now()),
                Progress::Done(..) => return,
            };
            if !time_left.is_zero() {
                state = self.login_wake.wait_timeout(state, time_left).unwrap().0;
                continue;
            }
            let mut task = state.login_deadline.take().unwrap();
            let (outcome, remaining) =
                match std::mem::replace(&mut task.progress, Progress::Waiting) {
                    Progress::Waiting => (Blocked::Timeout, MAX_RETRIES),
                    Progress::Retrying {
                        outcome, remaining, ..
                    } => (outcome, remaining - 1),
                    Progress::Done(..) => unreachable!(),
                };
            self.block_for_deadline(&mut state, &mut task, outcome, remaining);
            state.login_deadline = Some(task);
        }
    }

    pub fn login_deadline_status(&self, token: u64) -> LoginDeadlineStatus {
        let state = self.state.lock().unwrap();
        let Some(task) = state
            .login_deadline
            .as_ref()
            .filter(|task| task.token == token)
        else {
            return LoginDeadlineStatus::Stale;
        };
        match task.progress {
            Progress::Waiting => LoginDeadlineStatus::Pending,
            Progress::Retrying { .. } => LoginDeadlineStatus::ProtectionUnconfirmed,
            Progress::Done(status, _) => status,
        }
    }

    pub fn login_deadline_error(&self, token: u64) -> Option<String> {
        let state = self.state.lock().unwrap();
        state
            .login_deadline
            .as_ref()
            .filter(|task| task.token == token)
            .and_then(Self::deadline_error)
    }

    fn deadline_error(task: &LoginDeadline) -> Option<String> {
        match &task.progress {
            Progress::Waiting => None,
            Progress::Retrying { error, .. } => Some(error.clone()),
            Progress::Done(_, error) => error.clone(),
        }
    }

    pub fn has_pending_login_deadline(&self) -> bool {
        self.has_pending_deadline_locked(&self.state.lock().unwrap())
    }

    fn has_pending_deadline_locked(&self, state: &State) -> bool {
        state
            .login_deadline
            .as_ref()
            .is_some_and(|task| !matches!(task.progress, Progress::Done(..)))
    }

    pub fn cancel_login_deadline(&self, token: u64) {
        let mut state = self.state.lock().unwrap();
        if state
            .login_deadline
            .as_ref()
            .is_some_and(|task| task.token == token)
        {
            self.clear_login_deadline(&mut state);
        }
    }

    pub(super) fn deadline_owns_rules(&self, state: &State) -> bool {
        state.login_deadline.as_ref().is_some_and(|task| {
            !matches!(
                task.progress,
                Progress::Done(LoginDeadlineStatus::Finished, None)
            )
        })
    }

    pub(super) fn clear_login_deadline(&self, state: &mut State) {
        if state.login_deadline.take().is_some() {
            self.login_wake.notify_all();
        }
    }
}
