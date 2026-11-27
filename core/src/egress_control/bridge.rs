//! One-shot loopback bridge for probing a protected site through a proxy or
//! local direct connection (DESIGN.md §71).
//!
//! Rust opens the real outbound TCP stream (`upstream`, either via a proxy's
//! CONNECT handshake or directly to a resolved IP) and exposes it on a fresh
//! `127.0.0.1:<ephemeral>` listener for at most one connection from this very
//! process. The platform TLS probe (`EgressProbe` on macOS) connects to that
//! loopback port with SNI and certificate verification set to the real site
//! name and sends only `GET /cdn-cgi/trace`.

use super::{evidence_clock_ms, parse_response, read_trace, trace_request, EgressPath, Observation, ProbeHook, ProbeRequest};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) const PROXY_PROBE_TIMEOUT_MS: u64 = 4_000;
const BRIDGE_IO_TIMEOUT: Duration = Duration::from_millis(PROXY_PROBE_TIMEOUT_MS);

#[cfg(target_os = "macos")]
const LOOPBACK_IF: &str = "lo0";
#[cfg(not(target_os = "macos"))]
const LOOPBACK_IF: &str = "lo";

/// Opens an outbound TCP stream to `host:443` (or `peer_ip:443`) along `path`.
/// Returns `(stream, early_bytes_from_proxy, observed_peer_ip)`.
pub type RelayOpener = Arc<
    dyn Fn(&EgressPath, &str, Option<IpAddr>) -> Result<(TcpStream, Vec<u8>, Option<IpAddr>), String> + Send + Sync,
>;

fn no_sigpipe(stream: &TcpStream) {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let _ = socket2::SockRef::from(stream).set_nosigpipe(true);
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let _ = stream;
}

fn reset(stream: &TcpStream) {
    let _ = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO));
    let _ = stream.shutdown(Shutdown::Both);
}

#[cfg(target_os = "macos")]
fn owned_by_self(peer_port: u16) -> bool {
    crate::split_proxy::owner::owns(std::process::id() as i32, crate::split_proxy::Proto::Tcp, peer_port)
}

#[cfg(not(target_os = "macos"))]
fn owned_by_self(_peer_port: u16) -> bool {
    true
}

/// One-shot loopback listener that accepts at most one connection from this
/// process and bridges it to `upstream`.
pub(crate) struct OneShotBridge {
    port: u16,
    stop_flag: Arc<AtomicBool>,
    wake_write: Option<std::os::fd::OwnedFd>,
    thread: Option<std::thread::JoinHandle<bool>>,
}

impl OneShotBridge {
    pub(crate) fn start(upstream: TcpStream, early: Vec<u8>, timeout: Duration) -> io::Result<Self> {
        let listener = crate::child_io::creation(|| TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let (wake_read, wake_write) = crate::child_io::pipe()?;
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_bg = stop_flag.clone();
        let thread = std::thread::Builder::new()
            .name("egress-probe-bridge".into())
            .stack_size(128 * 1024)
            .spawn(move || run_bridge(listener, wake_read, upstream, early, timeout, stop_bg))?;
        Ok(Self {
            port,
            stop_flag,
            wake_write: Some(wake_write),
            thread: Some(thread),
        })
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn finish(mut self) -> bool {
        self.stop_flag.store(true, Ordering::Release);
        // Closing the write end wakes poll(wake_read) via POLLHUP with zero
        // risk of SIGPIPE when run_bridge already exited and dropped wake_read.
        drop(self.wake_write.take());
        self.thread.take().and_then(|t| t.join().ok()).unwrap_or(false)
    }
}

impl Drop for OneShotBridge {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Release);
        drop(self.wake_write.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn run_bridge(
    listener: TcpListener,
    wake_read: std::os::fd::OwnedFd,
    upstream: TcpStream,
    early: Vec<u8>,
    timeout: Duration,
    stop: Arc<AtomicBool>,
) -> bool {
    let deadline = Instant::now() + timeout;
    let client = loop {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return false;
        };
        let wait_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        let mut fds = [
            libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: wake_read.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, wait_ms) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        if rc == 0 || fds[1].revents != 0 {
            return false;
        }
        match crate::child_io::accept(&listener) {
            Ok((stream, peer)) => {
                no_sigpipe(&stream);
                let allowed = peer.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) && owned_by_self(peer.port());
                if allowed {
                    break stream;
                }
                // Refuse any connection from outside this process and keep
                // waiting (within the short deadline) for our own probe.
                reset(&stream);
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => continue,
            Err(_) => return false,
        }
    };
    // Close the listener immediately so no second connection can ever connect.
    drop(listener);
    let _ = client.set_nonblocking(false);
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nonblocking(false);
    let _ = upstream.set_nodelay(true);
    no_sigpipe(&upstream);
    let _ = client.set_read_timeout(Some(BRIDGE_IO_TIMEOUT));
    let _ = client.set_write_timeout(Some(BRIDGE_IO_TIMEOUT));
    let _ = upstream.set_read_timeout(Some(BRIDGE_IO_TIMEOUT));
    let _ = upstream.set_write_timeout(Some(BRIDGE_IO_TIMEOUT));

    if !early.is_empty() && (&client).write_all(&early).is_err() {
        let _ = upstream.shutdown(Shutdown::Both);
        let _ = client.shutdown(Shutdown::Both);
        return true;
    }

    std::thread::scope(|scope| {
        let (Ok(c_read), Ok(u_write)) = (client.try_clone(), upstream.try_clone()) else {
            return;
        };
        let up = std::thread::Builder::new().name("egress-probe-up".into()).spawn_scoped(scope, move || {
            pump_once(&c_read, &u_write);
            let _ = u_write.shutdown(Shutdown::Write);
        });
        pump_once(&upstream, &client);
        let _ = client.shutdown(Shutdown::Write);
        if let Ok(t) = up {
            let _ = t.join();
        }
    });
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
    true
}

fn pump_once(from: &TcpStream, to: &TcpStream) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match (&*from).read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                if (&*to).write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        }
    }
}

/// Probe `host` along `path` (Proxy or Local) via a one-shot loopback bridge
/// and the platform's TLS probe hook.
pub(super) fn probe_via_relay(
    hook: &ProbeHook,
    opener: &RelayOpener,
    path: &EgressPath,
    host: &str,
    peer_ip: Option<IpAddr>,
) -> Observation {
    let mut obs = Observation {
        host: host.into(),
        peer_address: peer_ip,
        path: Some(path.wire()),
        ..Default::default()
    };
    if host.is_empty() {
        obs.error = Some("看不到网站名".into());
        return obs;
    }
    let (upstream, early, actual_peer) = match opener(path, host, peer_ip) {
        Ok(opened) => opened,
        Err(reason) => {
            obs.error = Some(reason);
            return obs;
        }
    };
    obs.peer_address = actual_peer;
    let bridge = match OneShotBridge::start(upstream, early, Duration::from_millis(PROXY_PROBE_TIMEOUT_MS)) {
        Ok(b) => b,
        Err(_) => {
            obs.error = Some("出口检查通道没能建立".into());
            return obs;
        }
    };
    let req = ProbeRequest {
        host: host.into(),
        connect_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: bridge.port(),
        request: trace_request(host),
        alpn: vec!["http/1.1".to_string()],
        interface: LOOPBACK_IF.into(),
        timeout_ms: PROXY_PROBE_TIMEOUT_MS,
    };
    let mut probe_peer = None;
    let raw = hook(&req, &mut probe_peer);
    let answered_at = evidence_clock_ms();
    let _ = bridge.finish();
    if probe_peer.is_some_and(|p| p != IpAddr::V4(Ipv4Addr::LOCALHOST)) {
        obs.error = Some("探测对端与本地通道不符".into());
        return obs;
    }
    match raw.as_deref().and_then(parse_response) {
        None => obs.error = Some("连不上或没有回答".into()),
        Some(resp) => match read_trace(&resp) {
            Ok((country, exit)) => {
                obs.evidence_at_ms = answered_at;
                obs.country = Some(country);
                obs.ip = exit;
            }
            Err(e) => obs.error = Some(e),
        },
    }
    obs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shot_bridge_accepts_only_one_connection_and_splices_data() {
        // Fake remote server echoing received bytes back with a prefix.
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let remote_addr = remote.local_addr().unwrap();
        let server_thread = std::thread::spawn(move || {
            let (mut s, _) = remote.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).unwrap();
            let mut reply = b"OK:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            s.write_all(&reply).unwrap();
            let _ = s.shutdown(Shutdown::Both);
        });

        let upstream = TcpStream::connect(remote_addr).unwrap();
        let bridge = OneShotBridge::start(upstream, b"EARLY:".to_vec(), Duration::from_secs(3)).unwrap();
        let port = bridge.port();

        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client.write_all(b"ping").unwrap();
        let _ = client.shutdown(Shutdown::Write);
        let mut out = Vec::new();
        client.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"EARLY:OK:ping");

        // Second connection must be refused because the listener was dropped.
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err(), "one-shot port must be closed after first accept");
        assert!(bridge.finish());
        server_thread.join().unwrap();
    }

    #[test]
    fn one_shot_bridge_stops_immediately_when_unused() {
        let remote = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream = TcpStream::connect(remote.local_addr().unwrap()).unwrap();
        let start = Instant::now();
        let bridge = OneShotBridge::start(upstream, Vec::new(), Duration::from_secs(5)).unwrap();
        assert!(!bridge.finish());
        assert!(start.elapsed() < Duration::from_secs(1), "unused bridge must stop immediately, not wait for timeout");
    }
}
