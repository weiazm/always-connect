//! Ordering of visible proxy checks. The menu-bar process owns this ledger.
//! A network or saved configuration change invalidates prior requests.
use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::sync::{Mutex, OnceLock};

#[derive(Default)]
struct Slot {
    pending: Option<(u64, f64)>,
    again: bool,
    observed: f64,
    checked: f64,
}

#[derive(Default)]
struct Ledger {
    next: u64,
    since: f64,
    slots: HashMap<String, Slot>,
}

impl Ledger {
    fn reset(&mut self, now: f64) {
        self.since = now;
        self.slots.clear();
    }
    fn begin(&mut self, key: &str, now: f64, gap: f64, force: bool) -> u64 {
        let slot = self.slots.entry(key.to_owned()).or_default();
        if slot.pending.is_some() {
            slot.again |= force;
            return 0;
        }
        if !force && slot.checked > 0. && now - slot.checked < gap { return 0; }
        self.next = self.next.wrapping_add(1).max(1);
        slot.pending = Some((self.next, now));
        self.next
    }
    // -1 superseded, bit 0 publish, bit 1 one more user-requested check.
    fn finish(&mut self, key: &str, ticket: u64, now: f64) -> i32 {
        let Some(slot) = self.slots.get_mut(key) else { return -1 };
        let Some((current, start)) = slot.pending else { return -1 };
        if ticket != current { return -1; }
        slot.pending = None;
        slot.checked = now;
        let publish = slot.observed <= start;
        if publish { slot.observed = start; }
        i32::from(publish) | (i32::from(std::mem::take(&mut slot.again)) << 1)
    }
    fn traffic(&mut self, key: &str, at: f64) -> bool {
        if at <= self.since { return false; }
        let slot = self.slots.entry(key.to_owned()).or_default();
        if at <= slot.observed { return false; }
        slot.observed = at;
        true
    }
}

fn ledger() -> std::sync::MutexGuard<'static, Ledger> {
    static LEDGER: OnceLock<Mutex<Ledger>> = OnceLock::new();
    LEDGER.get_or_init(Default::default).lock().unwrap()
}

// The same clock in both App processes and the service, including across a
// wall-clock correction when a Mac reconnects.
#[no_mangle]
pub extern "C" fn ac_proxy_health_now() -> f64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

#[no_mangle]
pub extern "C" fn ac_proxy_health_reset(now: f64) { ledger().reset(now); }

#[no_mangle]
pub unsafe extern "C" fn ac_proxy_health_begin(key: *const c_char, now: f64, gap: f64, force: bool) -> u64 {
    if key.is_null() { return 0; }
    let Ok(key) = CStr::from_ptr(key).to_str() else { return 0 };
    ledger().begin(key, now, gap, force)
}

#[no_mangle]
pub unsafe extern "C" fn ac_proxy_health_finish(key: *const c_char, ticket: u64, now: f64) -> i32 {
    if key.is_null() { return -1; }
    let Ok(key) = CStr::from_ptr(key).to_str() else { return -1 };
    ledger().finish(key, ticket, now)
}

#[no_mangle]
pub unsafe extern "C" fn ac_proxy_health_traffic(key: *const c_char, at: f64) -> bool {
    if key.is_null() { return false; }
    let Ok(key) = CStr::from_ptr(key).to_str() else { return false };
    ledger().traffic(key, at)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn traffic_late_probes_and_network_changes() {
        let mut l = Ledger::default();
        let t = l.begin("a", 100., 30., false);
        assert_ne!(t, 0);
        assert_eq!(l.begin("a", 101., 30., true), 0);
        assert!(l.traffic("a", 102.));
        assert_eq!(l.finish("a", t, 103.), 2);
        assert!(!l.traffic("a", 102.));
        let t = l.begin("a", 104., 30., true);
        l.reset(105.);
        assert!(!l.traffic("a", 103.));
        let u = l.begin("a", 106., 30., false);
        assert_eq!(l.finish("a", t, 107.), -1);
        assert_eq!(l.finish("a", u, 108.), 1);
        assert_eq!(l.begin("a", 109., 30., false), 0);
    }
}
