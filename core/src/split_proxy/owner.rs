//! Which process owns a local socket (macOS libproc). A proxy running on
//! this Mac resolves the proxied name through the same system resolver
//! and connects to our address too; its own connections must not be sent
//! back to it (a loop). Offsets of `struct socket_fdinfo` are from the
//! macOS SDK's <sys/proc_info.h> (arm64 and x86_64 alike) and checked by
//! the tests below against real sockets.

use super::Proto;

#[cfg(target_os = "macos")]
mod imp {
    use super::Proto;

    const PROC_PIDLISTFDS: i32 = 1;
    const PROC_PIDFDSOCKETINFO: i32 = 3;
    const PROX_FDTYPE_SOCKET: u32 = 2;
    const SOCKET_FDINFO_SIZE: usize = 792;
    const SOI_PROTOCOL: usize = 180;
    const SOI_FAMILY: usize = 184;
    const SOI_KIND: usize = 256;
    const INSI_LPORT: usize = 268;
    const TCPSI_STATE: usize = 344;
    const SOCKINFO_IN: i32 = 1;
    const SOCKINFO_TCP: i32 = 2;
    const TSI_S_LISTEN: i32 = 1;

    use libc::{proc_listallpids, proc_pidfdinfo, proc_pidinfo};

    struct Socket { proto: i32, kind: i32, local_port: u16, state: i32 }

    fn int(buffer: &[u8], at: usize) -> i32 { i32::from_ne_bytes(buffer[at..at + 4].try_into().unwrap()) }

    fn sockets(pid: i32) -> Vec<Socket> {
        let mut fds = vec![[0u8; 8]; 256];
        let mut n;
        loop {
            let bytes = (fds.len() * 8) as libc::c_int;
            n = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), bytes) };
            if n <= 0 { return Vec::new(); }
            if (n as usize) < fds.len() * 8 || fds.len() >= 65536 { break; }
            fds.resize(fds.len() * 4, [0u8; 8]);
        }
        let mut out = Vec::new();
        let mut info = vec![0u8; SOCKET_FDINFO_SIZE];
        for entry in &fds[..n as usize / 8] {
            let fd = i32::from_ne_bytes(entry[..4].try_into().unwrap());
            let kind = u32::from_ne_bytes(entry[4..].try_into().unwrap());
            if kind != PROX_FDTYPE_SOCKET { continue; }
            let got = unsafe { proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, info.as_mut_ptr().cast(), SOCKET_FDINFO_SIZE as libc::c_int) };
            if got as usize != SOCKET_FDINFO_SIZE { continue; }
            let family = int(&info, SOI_FAMILY);
            let kind = int(&info, SOI_KIND);
            if (family != libc::AF_INET && family != libc::AF_INET6) || (kind != SOCKINFO_IN && kind != SOCKINFO_TCP) { continue; }
            out.push(Socket {
                proto: int(&info, SOI_PROTOCOL),
                kind,
                local_port: u16::from_be(int(&info, INSI_LPORT) as u16),
                state: if kind == SOCKINFO_TCP { int(&info, TCPSI_STATE) } else { -1 },
            });
        }
        out
    }

    fn pids() -> Vec<i32> {
        let count = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 { return Vec::new(); }
        let mut pids = vec![0i32; count as usize + 64];
        let n = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), (pids.len() * 4) as libc::c_int) };
        pids.truncate(n.max(0) as usize);
        pids.retain(|p| *p > 0);
        pids
    }

    pub fn listeners(port: u16) -> Vec<i32> {
        pids().into_iter().filter(|pid| sockets(*pid).iter().any(|s|
            s.kind == SOCKINFO_TCP && s.state == TSI_S_LISTEN && s.local_port == port)).collect()
    }

    pub fn owns(pid: i32, proto: Proto, local_port: u16) -> bool {
        let wanted = if proto == Proto::Tcp { libc::IPPROTO_TCP } else { libc::IPPROTO_UDP };
        sockets(pid).iter().any(|s| s.proto == wanted && s.local_port == local_port && s.state != TSI_S_LISTEN)
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::Proto;
    pub fn listeners(_port: u16) -> Vec<i32> { Vec::new() }
    pub fn owns(_pid: i32, _proto: Proto, _local_port: u16) -> bool { false }
}

/// Processes listening on TCP `port` (a proxy's own port).
pub fn listeners(port: u16) -> Vec<i32> { imp::listeners(port) }

/// Whether `pid` has a (non-listening) socket of `proto` on `local_port`.
pub fn owns(pid: i32, proto: Proto, local_port: u16) -> bool { imp::owns(pid, proto, local_port) }

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    #[test]
    fn finds_this_process_by_its_sockets() {
        let me = std::process::id() as i32;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(listeners(port).contains(&me), "a listening TCP socket");
        let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let client_port = client.local_addr().unwrap().port();
        assert!(owns(me, Proto::Tcp, client_port), "a connected TCP socket");
        assert!(!owns(me, Proto::Udp, client_port));
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        assert!(owns(me, Proto::Udp, udp_port), "a UDP socket");
        drop(client);
        drop(udp);
        assert!(!owns(me, Proto::Udp, udp_port));
        assert!(listeners(1).is_empty() || !listeners(1).contains(&me));
    }
}
