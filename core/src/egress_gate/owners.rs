//! Which protected app a new connection belongs to (DESIGN §66.24). The
//! gate runs as root and reads the socket tables of the processes whose
//! path matches a protected app: a bundle ("/Applications/Example.app",
//! the bundle and everything inside it) or an executable file name
//! ("example-cli"). Every other connection is none of the gate's business.

use super::GroupId;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppRule {
    pub group: GroupId,
    pub patterns: Vec<String>,
}

pub fn path_matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    if pattern.starts_with('/') {
        let root = pattern.trim_end_matches('/');
        !root.is_empty() && (path == root || path.strip_prefix(root).is_some_and(|rest| rest.starts_with('/')))
    } else {
        path.rsplit('/').next() == Some(pattern)
    }
}

pub trait FlowOwners: Send {
    /// Some app is protected: the gate decides by owner, not by name.
    fn active(&self) -> bool;
    /// The protected app's group whose socket of `proto` (6 TCP, 17 UDP)
    /// uses `local_port`, if any.
    fn group_for(&mut self, proto: u8, local_port: u16, now: Instant) -> Option<GroupId>;
}

pub struct NoOwners;

impl FlowOwners for NoOwners {
    fn active(&self) -> bool {
        false
    }
    fn group_for(&mut self, _: u8, _: u16, _: Instant) -> Option<GroupId> {
        None
    }
}

/// Processes are matched again at most this often; a miss rescans the
/// sockets of the matched processes only (well under a millisecond).
const PIDS_REFRESH: Duration = Duration::from_secs(2);
/// A new process gets this soon to appear before a miss is final.
const PIDS_MISS_REFRESH: Duration = Duration::from_millis(200);

pub struct ProcessOwners {
    rules: Vec<AppRule>,
    pids: Vec<(i32, GroupId)>,
    pids_at: Option<Instant>,
    ports: HashMap<(u8, u16), GroupId>,
}

impl ProcessOwners {
    pub fn new(rules: Vec<AppRule>) -> Self {
        let rules = rules.into_iter().filter(|rule| rule.patterns.iter().any(|p| !p.trim().is_empty())).collect();
        Self { rules, pids: Vec::new(), pids_at: None, ports: HashMap::new() }
    }

    fn group_of_path(&self, path: &str) -> Option<GroupId> {
        self.rules.iter().find(|rule| rule.patterns.iter().any(|p| path_matches(p, path))).map(|rule| rule.group)
    }

    fn refresh_pids(&mut self, now: Instant) {
        self.pids = platform::all_pids()
            .into_iter()
            .filter_map(|pid| platform::path(pid).and_then(|path| self.group_of_path(&path)).map(|group| (pid, group)))
            .collect();
        self.pids_at = Some(now);
    }

    fn scan_ports(&mut self) {
        self.ports.clear();
        for &(pid, group) in &self.pids {
            for key in platform::local_ports(pid) {
                self.ports.insert(key, group);
            }
        }
    }
}

impl FlowOwners for ProcessOwners {
    fn active(&self) -> bool {
        !self.rules.is_empty()
    }

    fn group_for(&mut self, proto: u8, local_port: u16, now: Instant) -> Option<GroupId> {
        if self.rules.is_empty() {
            return None;
        }
        if self.pids_at.is_none_or(|at| now.duration_since(at) >= PIDS_REFRESH) {
            self.refresh_pids(now);
        }
        // Ports are reused: never trust an older scan for a new connection.
        self.scan_ports();
        if let Some(group) = self.ports.get(&(proto, local_port)) {
            return Some(*group);
        }
        if self.pids_at.is_some_and(|at| now.duration_since(at) >= PIDS_MISS_REFRESH) {
            self.refresh_pids(now);
            self.scan_ports();
            return self.ports.get(&(proto, local_port)).copied();
        }
        None
    }
}

#[cfg(target_os = "macos")]
mod platform {
    // libproc's socket record (sys/proc_info.h, struct socket_fdinfo) is not
    // in the libc crate. Apple Silicon offsets, checked by the test below.
    const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
    const SOCKET_FDINFO_SIZE: usize = 792;
    const SOI_PROTOCOL: usize = 180;
    const SOI_KIND: usize = 256;
    const INSI_LPORT: usize = 268;
    const SOCKINFO_IN: i32 = 1;
    const SOCKINFO_TCP: i32 = 2;

    pub fn all_pids() -> Vec<i32> {
        let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 {
            return Vec::new();
        }
        let mut pids = vec![0i32; count as usize + 64];
        let bytes = (pids.len() * std::mem::size_of::<i32>()) as libc::c_int;
        let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        pids.truncate(got.max(0) as usize);
        pids.retain(|pid| *pid > 0);
        pids
    }

    pub fn path(pid: i32) -> Option<String> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let len = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
        if len <= 0 {
            return None;
        }
        buf.truncate(len as usize);
        String::from_utf8(buf).ok()
    }

    fn read_i32(buf: &[u8], at: usize) -> i32 {
        i32::from_ne_bytes(buf[at..at + 4].try_into().expect("in range"))
    }

    pub fn local_ports(pid: i32) -> Vec<(u8, u16)> {
        let size = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        if size <= 0 {
            return Vec::new();
        }
        let entry = std::mem::size_of::<libc::proc_fdinfo>();
        let mut fds: Vec<libc::proc_fdinfo> = Vec::with_capacity(size as usize / entry + 16);
        let capacity = (fds.capacity() * entry) as libc::c_int;
        let got = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), capacity) };
        if got <= 0 {
            return Vec::new();
        }
        unsafe { fds.set_len((got as usize / entry).min(fds.capacity())) };
        let mut ports = Vec::new();
        let mut info = vec![0u8; SOCKET_FDINFO_SIZE];
        for fd in fds.iter().filter(|fd| fd.proc_fdtype as libc::c_int == libc::PROX_FDTYPE_SOCKET) {
            let read = unsafe {
                libc::proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, info.as_mut_ptr().cast(), SOCKET_FDINFO_SIZE as libc::c_int)
            };
            if read as usize != SOCKET_FDINFO_SIZE {
                continue;
            }
            let kind = read_i32(&info, SOI_KIND);
            if kind != SOCKINFO_TCP && kind != SOCKINFO_IN {
                continue;
            }
            let proto = read_i32(&info, SOI_PROTOCOL);
            let proto = match proto {
                6 | 17 => proto as u8,
                _ => continue,
            };
            let port = u16::from_be(read_i32(&info, INSI_LPORT) as u16);
            if port != 0 {
                ports.push((proto, port));
            }
        }
        ports
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    pub fn all_pids() -> Vec<i32> {
        Vec::new()
    }
    pub fn path(_: i32) -> Option<String> {
        None
    }
    pub fn local_ports(_: i32) -> Vec<(u8, u16)> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_match_a_bundle_and_everything_inside_or_an_executable_name() {
        let bundle = "/Applications/Example.app";
        assert!(path_matches(bundle, "/Applications/Example.app"));
        assert!(path_matches(bundle, "/Applications/Example.app/Contents/Frameworks/Helper (Renderer).app/Contents/MacOS/Helper"));
        assert!(path_matches("/Applications/Example.app/", "/Applications/Example.app/Contents/MacOS/Example"));
        assert!(!path_matches(bundle, "/Applications/Example.app2/Contents/MacOS/x"));
        assert!(!path_matches(bundle, "/Applications/Other.app/Contents/MacOS/Example.app"));
        assert!(path_matches("example-cli", "/opt/tools/lib/example/bin/example-cli"));
        assert!(!path_matches("example-cli", "/opt/tools/lib/example/bin/example-cli-helper"));
        assert!(!path_matches("", "/bin/sh") && !path_matches("/", "/bin/sh"));
    }

    #[test]
    fn no_rules_never_owns_a_connection() {
        let mut owners = ProcessOwners::new(vec![AppRule { group: 1, patterns: vec![" ".into()] }]);
        assert!(!owners.active());
        assert_eq!(owners.group_for(6, 443, Instant::now()), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn finds_this_test_process_by_its_connected_local_port() {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let port = client.local_addr().unwrap().port();
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_name().unwrap().to_string_lossy().into_owned();
        let mut owners = ProcessOwners::new(vec![AppRule { group: 7, patterns: vec![name] }]);
        assert!(owners.active());
        assert_eq!(owners.group_for(6, port, Instant::now()), Some(7), "the struct offsets read the right local port");
        assert_eq!(owners.group_for(17, port, Instant::now()), None, "the protocol is part of the key");
        let mut others = ProcessOwners::new(vec![AppRule { group: 7, patterns: vec!["/nonexistent/Example.app".into()] }]);
        assert_eq!(others.group_for(6, port, Instant::now()), None);
        drop(client);
    }
}
