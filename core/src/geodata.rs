//! The site lists (geosite:) and geoip:cn as the App uses them (DESIGN.md
//! §66.30; user 2026-11-25: "这种逻辑肯定要下沉到rust做").
//!
//! geosite.txt (the text format of `geosite.rs`) is downloaded by the App
//! into Application Support and read here in place: memory-mapped once
//! (clean pages the system can drop), re-mapped when its path, size or
//! modification time changes. A list is located only when asked, by a scan
//! for its "[name]" line, and only those positions are kept; there is never
//! an index of all lists. Expansion for the background service produces one
//! newline-joined text (split list) or one JSON document (exit protection),
//! so the App never holds the expanded entries as separate strings.
//!
//! Installing a downloaded `dlc.dat` (conversion, the lists the user's
//! rules name, whether one of them changed, atomic write of the text and the
//! version file) is here too; the App keeps only the download and SHA-256.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::egress_control::valid_rule;

struct Mapping {
    path: PathBuf,
    stamp: (i64, i64, u64),
    ptr: *mut libc::c_void,
    len: usize,
    /// Positions of the lists asked for so far (None = not in the file).
    found: HashMap<String, Option<(usize, usize)>>,
}

// The mapping is read-only and only touched under the mutex.
unsafe impl Send for Mapping {}

impl Mapping {
    fn bytes(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: `ptr` maps `len` readable bytes until `munmap` in Drop.
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if self.len > 0 {
            // SAFETY: the same region `mmap` returned.
            unsafe { libc::munmap(self.ptr, self.len) };
        }
    }
}

#[derive(Default)]
struct State {
    geosite: PathBuf,
    geoip: PathBuf,
    mapping: Option<Mapping>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn lock() -> std::sync::MutexGuard<'static, Option<State>> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Where the App keeps the files; set once per process (and by tests).
pub fn configure(geosite: &Path, geoip: &Path) {
    let mut state = lock();
    let same = state.as_ref().is_some_and(|s| s.geosite == geosite && s.geoip == geoip);
    if !same {
        *state = Some(State { geosite: geosite.to_path_buf(), geoip: geoip.to_path_buf(), mapping: None });
    }
}

fn stamp(path: &Path) -> Option<(i64, i64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.mtime(), meta.mtime_nsec(), meta.size()))
}

fn map(path: &Path, stamp: (i64, i64, u64)) -> Option<Mapping> {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::File::open(path).ok()?;
    let len = usize::try_from(stamp.2).ok()?;
    let ptr = if len == 0 {
        std::ptr::null_mut()
    } else {
        // SAFETY: a private read-only mapping of an open file; checked below.
        let ptr = unsafe {
            libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_PRIVATE, file.as_raw_fd(), 0)
        };
        if ptr == libc::MAP_FAILED {
            return None;
        }
        ptr
    };
    Some(Mapping { path: path.to_path_buf(), stamp, ptr, len, found: HashMap::new() })
}

/// Runs `f` on the current file (re-mapped if it changed); None when there
/// is no file or the paths were never set.
fn with_mapping<T>(f: impl FnOnce(&mut Mapping) -> T) -> Option<T> {
    let mut guard = lock();
    let state = guard.as_mut()?;
    let Some(now) = stamp(&state.geosite) else {
        state.mapping = None;
        return None;
    };
    let fresh = state.mapping.as_ref().is_some_and(|m| m.path == state.geosite && m.stamp == now);
    if !fresh {
        state.mapping = map(&state.geosite, now);
    }
    state.mapping.as_mut().map(f)
}

/// The lines of list `name` in `data`: after "[name]\n" up to the next
/// line that starts with "[". Scans only for that header.
pub fn list_range(data: &[u8], name: &str) -> Option<(usize, usize)> {
    let header = format!("[{name}]\n");
    let header = header.as_bytes();
    let mut i = 0;
    let mut start = None;
    while i < data.len() {
        if data[i] == b'[' && data[i..].starts_with(header) {
            start = Some(i + header.len());
            break;
        }
        i = data[i..].iter().position(|&b| b == b'\n').map_or(data.len(), |p| i + p + 1);
    }
    let start = start?;
    let mut end = start;
    while end < data.len() && data[end] != b'[' {
        end = data[end..].iter().position(|&b| b == b'\n').map_or(data.len(), |p| end + p + 1);
    }
    Some((start, end))
}

fn located(m: &mut Mapping, name: &str) -> Option<(usize, usize)> {
    if let Some(known) = m.found.get(name) {
        return *known;
    }
    let range = list_range(m.bytes(), name);
    m.found.insert(name.to_owned(), range);
    range
}

/// One stored line ("d:x @a") as a background-service entry when it
/// carries `attribute` (or no attribute is asked for).
fn entry<'a>(line: &'a [u8], attribute: Option<&str>) -> Option<(&'static str, &'a str)> {
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split(' ');
    let head = parts.next()?;
    if head.len() < 3 || head.as_bytes()[1] != b':' {
        return None;
    }
    let prefix = match head.as_bytes()[0] {
        b'd' => "domain:",
        b'f' => "full:",
        b'k' => "keyword:",
        b'r' => "regexp:",
        _ => return None,
    };
    if let Some(attribute) = attribute {
        if !parts.any(|p| p.strip_prefix('@') == Some(attribute)) {
            return None;
        }
    }
    Some((prefix, &head[2..]))
}

fn each_entry(name: &str, attribute: Option<&str>, mut f: impl FnMut(&'static str, &str)) -> bool {
    with_mapping(|m| {
        let Some((start, end)) = located(m, name) else { return false };
        for line in m.bytes()[start..end].split(|&b| b == b'\n') {
            if let Some((prefix, value)) = entry(line, attribute) {
                f(prefix, value);
            }
        }
        true
    })
    .unwrap_or(false)
}

/// The site lists have been downloaded.
pub fn available() -> bool {
    lock().as_ref().is_some_and(|s| s.geosite.is_file())
}

pub fn has_list(name: &str) -> bool {
    with_mapping(|m| located(m, name).is_some()).unwrap_or(false)
}

/// How many rules list `name` has (with `attribute`: only those carrying
/// it); counted in place, nothing kept.
pub fn rule_count(name: &str, attribute: Option<&str>) -> usize {
    let mut count = 0;
    each_entry(name, attribute, |_, _| count += 1);
    count
}

fn geoip_cn() -> Vec<String> {
    let path = lock().as_ref().map(|s| s.geoip.clone());
    let text = path.and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
    text.lines().map(str::trim).filter(|l| crate::dns_forwarder::cidr_range(l).is_some())
        .map(|l| format!("ipcidr:{l}")).collect()
}

/// The background service's entries for the stored rule lines, in order,
/// without repeats. Networks become "ipcidr:" entries only when asked for
/// (exit protection checks them; the split list routes them elsewhere).
pub fn expand<'a>(lines: impl IntoIterator<Item = &'a str>, networks: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |entry: String, out: &mut Vec<String>| {
        if seen.insert(entry.clone()) {
            out.push(entry);
        }
    };
    for raw in lines {
        let line = raw.trim();
        if line.is_empty() || !valid_rule(line, false) {
            continue;
        }
        match line.split_once(':') {
            Some(("geosite", list)) => {
                let (name, attribute) = match list.split_once('@') {
                    Some((n, a)) => (n.to_ascii_lowercase(), Some(a.to_ascii_lowercase())),
                    None => (list.to_ascii_lowercase(), None),
                };
                each_entry(&name, attribute.as_deref(), |prefix, value| push(format!("{prefix}{value}"), &mut out));
            }
            Some(("geoip", code)) if code.eq_ignore_ascii_case("cn") => {
                for entry in geoip_cn() {
                    push(entry, &mut out);
                }
            }
            Some(("domain", name)) => push(name.to_owned(), &mut out),
            Some(_) => push(line.to_owned(), &mut out),
            None if crate::dns_forwarder::cidr_range(line).is_some() => {
                if networks {
                    push(format!("ipcidr:{line}"), &mut out);
                }
            }
            None => push(line.to_owned(), &mut out),
        }
    }
    out
}

/// The exit-protection settings with each enabled rule's `matches` filled
/// in (and any stale ones dropped), as the background service takes them.
pub fn expand_egress(config: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(config).ok()?;
    let enabled = value.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let groups = value.get_mut("groups")?.as_array_mut()?;
    for group in groups {
        let group = group.as_object_mut()?;
        group.remove("matches");
        if !enabled || !group.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
            continue;
        }
        let sites: Vec<String> = group.get("sites").and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_owned)).collect())
            .unwrap_or_default();
        let matches = expand(sites.iter().map(String::as_str), true);
        group.insert("matches".into(), serde_json::Value::from(matches));
    }
    serde_json::to_string(&value).ok()
}

/// Puts a downloaded and hash-checked `dlc.dat` in place in `dir`
/// (geosite.txt and "version": tag and hash). Returns why not (nothing
/// written then), and whether a list in `used` differs from before. The
/// text goes straight to a temporary file list by list and the old file is
/// read mapped, so neither is ever held whole in memory.
pub fn install(dat: &[u8], tag: &str, hash: &str, dir: &Path, used: &[String]) -> (Option<String>, bool) {
    use std::io::Write;
    if std::fs::create_dir_all(dir).is_err() {
        return (Some("清单写不进去".into()), false);
    }
    let target = dir.join("geosite.txt");
    let old = stamp(&target).and_then(|s| map(&target, s));
    let mut wanted: Vec<&str> = used.iter().map(String::as_str).collect();
    wanted.sort_unstable();
    wanted.dedup();
    let mut present = HashSet::new();
    let mut changed = old.is_none();
    let temp = dir.join(".geosite.txt.tmp");
    let converted = std::fs::File::create(&temp).map_err(|_| "清单写不进去").and_then(|file| {
        let mut file = std::io::BufWriter::with_capacity(64 * 1024, file);
        crate::geosite::convert(dat, |name, list| {
            if wanted.binary_search(&name).is_ok() {
                present.insert(name.to_owned());
                if let Some(old) = &old {
                    let before = list_range(old.bytes(), name).map(|(s, e)| &old.bytes()[s..e]);
                    let header = name.len() + 3;
                    if before != Some(&list.as_bytes()[header..]) {
                        changed = true;
                    }
                }
            }
            file.write_all(list.as_bytes())
        })?;
        file.flush().map_err(|_| "清单写不进去")
    });
    let fail = |error: String| {
        let _ = std::fs::remove_file(&temp);
        (Some(error), false)
    };
    if let Err(error) = converted {
        return fail(if error == "清单写不进去" { error.into() } else { "清单内容不完整".into() });
    }
    if let Some(missing) = wanted.iter().find(|n| !present.contains(**n)) {
        return fail(format!("新清单里没有 geosite:{missing}，先不更新"));
    }
    drop(old);
    let version = dir.join(".version.tmp");
    let written = std::fs::rename(&temp, &target)
        .and_then(|_| std::fs::write(&version, format!("{tag}\n{hash}\n")))
        .and_then(|_| std::fs::rename(&version, dir.join("version")));
    match written {
        Ok(()) => (None, changed),
        Err(_) => fail("清单写不进去".into()),
    }
}

// ------------------------------------------------------------------ FFI

fn c_str(p: *const libc::c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the App passes NUL-terminated strings it owns.
    unsafe { std::ffi::CStr::from_ptr(p) }.to_str().ok().map(str::to_owned)
}

fn out(text: String) -> *mut libc::c_char {
    CString::new(text).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn ac_geodata_configure(geosite: *const libc::c_char, geoip: *const libc::c_char) {
    if let (Some(site), Some(ip)) = (c_str(geosite), c_str(geoip)) {
        configure(Path::new(&site), Path::new(&ip));
    }
}

#[no_mangle]
pub extern "C" fn ac_geodata_available() -> bool {
    available()
}

#[no_mangle]
pub extern "C" fn ac_geodata_has_list(name: *const libc::c_char) -> bool {
    c_str(name).is_some_and(|n| has_list(&n))
}

/// Rules in list `name` (attribute may be null).
#[no_mangle]
pub extern "C" fn ac_geodata_rule_count(name: *const libc::c_char, attribute: *const libc::c_char) -> i64 {
    let Some(name) = c_str(name) else { return 0 };
    rule_count(&name, c_str(attribute).as_deref()) as i64
}

/// Newline-joined rule lines in, newline-joined entries out.
#[no_mangle]
pub extern "C" fn ac_geodata_expand(lines: *const libc::c_char, networks: bool) -> *mut libc::c_char {
    let lines = c_str(lines).unwrap_or_default();
    out(expand(lines.lines(), networks).join("\n"))
}

#[no_mangle]
pub extern "C" fn ac_geodata_expand_egress(config: *const libc::c_char) -> *mut libc::c_char {
    c_str(config).and_then(|c| expand_egress(&c)).map(out).unwrap_or(std::ptr::null_mut())
}

/// `{"error": "…"|null, "changed": bool}`.
#[no_mangle]
pub extern "C" fn ac_geodata_install(
    dat: *const u8, len: usize, tag: *const libc::c_char, hash: *const libc::c_char,
    dir: *const libc::c_char, used: *const libc::c_char,
) -> *mut libc::c_char {
    let (Some(tag), Some(hash), Some(dir)) = (c_str(tag), c_str(hash), c_str(dir)) else {
        return out(r#"{"error":"清单写不进去","changed":false}"#.into());
    };
    let bytes = if dat.is_null() || len == 0 {
        &[][..]
    } else {
        // SAFETY: the App passes a buffer it owns for the length it states.
        unsafe { std::slice::from_raw_parts(dat, len) }
    };
    let used: Vec<String> = c_str(used).unwrap_or_default().lines()
        .map(str::trim).filter(|l| !l.is_empty()).map(str::to_owned).collect();
    let (error, changed) = install(bytes, &tag, &hash, Path::new(&dir), &used);
    out(serde_json::json!({ "error": error, "changed": changed }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test owns the process-wide paths at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ac-geodata-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const LISTS: &str = "[alpha]\nd:alpha.example\nf:www.alpha.example @cn\nk:alpha\nr:^a\\d+\\.alpha\\.example$ @ads @cn\n\
[beta]\nd:beta.example\nd:alpha.example\n[empty]\n";

    #[test]
    fn lists_are_found_counted_filtered_and_expanded_in_place() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let dir = scratch("lookup");
        std::fs::write(dir.join("geosite.txt"), LISTS).unwrap();
        std::fs::write(dir.join("geoip-cn.txt"), "198.51.100.0/24\nnot a network\n203.0.113.0/24\n").unwrap();
        configure(&dir.join("geosite.txt"), &dir.join("geoip-cn.txt"));
        assert!(available());
        assert!(has_list("alpha") && has_list("empty") && !has_list("alph") && !has_list("gamma"));
        assert_eq!(rule_count("alpha", None), 4);
        assert_eq!(rule_count("alpha", Some("cn")), 2);
        assert_eq!(rule_count("alpha", Some("ads")), 1);
        assert_eq!(rule_count("empty", None), 0);
        let split = expand(["geosite:alpha@cn", "example.org", "10.0.0.0/8", "geosite:beta", "geoip:cn", "full:x.example"], false);
        assert_eq!(split, [
            "full:www.alpha.example", r"regexp:^a\d+\.alpha\.example$", "example.org",
            "domain:beta.example", "domain:alpha.example", "ipcidr:198.51.100.0/24", "ipcidr:203.0.113.0/24",
            "full:x.example",
        ]);
        let egress = expand(["10.0.0.0/8", "domain:plain.example", "geosite:nosuch"], true);
        assert_eq!(egress, ["ipcidr:10.0.0.0/8", "plain.example"]);
        // A changed file is read again.
        std::fs::write(dir.join("geosite.txt"), "[alpha]\nd:changed.example\n").unwrap();
        assert_eq!(expand(["geosite:alpha"], false), ["domain:changed.example"]);
        assert!(!has_list("beta"));
        std::fs::remove_file(dir.join("geosite.txt")).unwrap();
        assert!(!available() && !has_list("alpha") && expand(["geosite:alpha"], false).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn exit_protection_settings_get_matches_for_enabled_rules_only() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let dir = scratch("egress");
        std::fs::write(dir.join("geosite.txt"), LISTS).unwrap();
        configure(&dir.join("geosite.txt"), &dir.join("none.txt"));
        let config = r#"{"enabled":true,"groups":[
            {"id":1,"name":"a","enabled":true,"sites":["geosite:beta","192.0.2.0/24","beta.example"],"expect":["ZZ"],"matches":["stale"]},
            {"id":2,"name":"b","enabled":false,"sites":["geosite:alpha"],"expect":["ZZ"],"matches":["stale"]}]}"#;
        let out: serde_json::Value = serde_json::from_str(&expand_egress(config).unwrap()).unwrap();
        assert_eq!(out["groups"][0]["matches"], serde_json::json!(["domain:beta.example", "domain:alpha.example", "ipcidr:192.0.2.0/24", "beta.example"]));
        assert!(out["groups"][1].get("matches").is_none());
        assert_eq!(out["groups"][0]["expect"], serde_json::json!(["ZZ"]), "other fields are kept");
        let off = expand_egress(&config.replacen("\"enabled\":true", "\"enabled\":false", 1)).unwrap();
        assert!(!off.contains("matches"));
        // Before the download a list-only rule is valid with no matches.
        std::fs::remove_file(dir.join("geosite.txt")).unwrap();
        let only = r#"{"enabled":true,"groups":[{"id":3,"name":"l","enabled":true,"sites":["geosite:beta"],"expect":["ZZ"]}]}"#;
        let sent = expand_egress(only).unwrap();
        assert!(sent.contains(r#""matches":[]"#));
        let cfg: crate::egress_control::EgressConfig = serde_json::from_str(&sent).unwrap();
        assert!(cfg.valid());
        let _ = std::fs::remove_dir_all(dir);
    }

    fn catalogue(alpha: &[&str], extra: Option<&str>) -> Vec<u8> {
        fn varint(mut v: u64, out: &mut Vec<u8>) {
            loop {
                let b = (v & 0x7F) as u8;
                v >>= 7;
                if v == 0 { out.push(b); return; }
                out.push(b | 0x80);
            }
        }
        fn field(n: u64, payload: &[u8], out: &mut Vec<u8>) {
            varint(n << 3 | 2, out);
            varint(payload.len() as u64, out);
            out.extend_from_slice(payload);
        }
        fn site(name: &str, domains: &[String]) -> Vec<u8> {
            let mut s = Vec::new();
            field(1, name.as_bytes(), &mut s);
            for d in domains {
                let mut e = Vec::new();
                varint(1 << 3, &mut e);
                varint(2, &mut e);
                field(2, d.as_bytes(), &mut e);
                field(2, &e, &mut s);
            }
            s
        }
        let mut out = Vec::new();
        field(1, &site("ALPHA", &alpha.iter().map(|s| s.to_string()).collect::<Vec<_>>()), &mut out);
        if let Some(extra) = extra {
            field(1, &site("EXTRA", &[extra.to_string()]), &mut out);
        }
        for i in 0..crate::geosite::MIN_LISTS {
            let domains: Vec<String> = (0..41).map(|j| format!("d{j}.l{i}.example")).collect();
            field(1, &site(&format!("list{i:04}"), &domains), &mut out);
        }
        out
    }

    #[test]
    fn installing_reports_whether_a_used_list_changed_and_refuses_a_missing_one() {
        let dir = scratch("install");
        let used = vec!["alpha".to_string()];
        let first = catalogue(&["alpha.example"], None);
        assert_eq!(install(&first, "1", "h1", &dir, &used), (None, true), "the first download always counts as a change");
        assert_eq!(std::fs::read_to_string(dir.join("version")).unwrap(), "1\nh1\n");
        let unrelated = catalogue(&["alpha.example"], Some("extra.example"));
        assert_eq!(install(&unrelated, "2", "h2", &dir, &used), (None, false), "a list nobody uses changed");
        assert!(std::fs::read_to_string(dir.join("geosite.txt")).unwrap().contains("[extra]"));
        let grown = catalogue(&["alpha.example", "more.example"], None);
        assert_eq!(install(&grown, "3", "h3", &dir, &used), (None, true));
        let before = std::fs::read(dir.join("geosite.txt")).unwrap();
        let (error, _) = install(&grown, "4", "h4", &dir, &["needed".to_string()]);
        assert_eq!(error.as_deref(), Some("新清单里没有 geosite:needed，先不更新"));
        assert_eq!(install(b"junk", "5", "h5", &dir, &used).0.as_deref(), Some("清单内容不完整"));
        assert_eq!(std::fs::read(dir.join("geosite.txt")).unwrap(), before, "refusals change nothing");
        assert_eq!(std::fs::read_to_string(dir.join("version")).unwrap(), "3\nh3\n");
        let _ = std::fs::remove_dir_all(dir);
    }
}
