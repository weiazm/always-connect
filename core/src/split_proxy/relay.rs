//! The service's end of the redirect: TCP connections and UDP flows that
//! pf sent here, carried through the proxy their rules name.

use super::protocol::{no_sigpipe, open_through, udp_associate, udp_unwrap, udp_wrap};
use super::{Kind, Routing, Target};
use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Simultaneous proxied connections; more are reset.
const MAX_CONNECTIONS: usize = 256;
/// Simultaneous UDP flows (app address + destination); more are dropped.
const MAX_FLOWS: usize = 256;
/// A UDP flow with no traffic either way this long is closed.
const UDP_IDLE: Duration = Duration::from_secs(120);
/// How often an open flow's thread looks at its idle time and the stop
/// flag (only while a flow exists; none when UDP is unused).
const UDP_CHECK: Duration = Duration::from_secs(10);
/// A proxy that refused a flow is not asked again for this long.
const UDP_RETRY: Duration = Duration::from_secs(15);
const STACK: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto { Tcp, Udp }

/// The address a redirected packet was originally sent to, from the
/// app's (peer) and our (local) addresses.
pub type OriginalDestination = Arc<dyn Fn(Proto, SocketAddrV4, SocketAddrV4) -> Option<SocketAddrV4> + Send + Sync>;

/// pf's record of a redirected connection or flow (DIOCNATLOOK; root).
#[cfg(target_os = "macos")]
pub fn pf_original_destination() -> io::Result<OriginalDestination> {
    use std::os::fd::{FromRawFd, OwnedFd};
    #[repr(C, align(4))]
    struct NatLook {
        saddr: [u8; 16], daddr: [u8; 16], rsaddr: [u8; 16], rdaddr: [u8; 16],
        sxport: [u8; 4], dxport: [u8; 4], rsxport: [u8; 4], rdxport: [u8; 4],
        af: u8, proto: u8, proto_variant: u8, direction: u8,
    }
    const _: () = assert!(std::mem::size_of::<NatLook>() == 84);
    // _IOWR('D', 23, struct pfioc_natlook)
    const DIOCNATLOOK: libc::c_ulong = 0xC000_0000 | (84 << 16) | ((b'D' as libc::c_ulong) << 8) | 23;
    const PF_OUT: u8 = 2;
    let raw = unsafe { libc::open(c"/dev/pf".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if raw < 0 { return Err(io::Error::last_os_error()); }
    let pf = Arc::new(unsafe { OwnedFd::from_raw_fd(raw) });
    Ok(Arc::new(move |proto, peer: SocketAddrV4, local: SocketAddrV4| {
        // xnu keys UDP states by their external filter mode as well (kept in
        // proto_variant: 0, then APD 1, AD 2, EI 3); TCP ignores it. Measured
        // on the CI Mac: with 0 alone every UDP lookup missed.
        let variants: &[u8] = if proto == Proto::Tcp { &[0] } else { &[1, 0, 2, 3] };
        variants.iter().find_map(|&variant| {
            let mut look = NatLook {
                saddr: [0; 16], daddr: [0; 16], rsaddr: [0; 16], rdaddr: [0; 16],
                sxport: [0; 4], dxport: [0; 4], rsxport: [0; 4], rdxport: [0; 4],
                af: libc::AF_INET as u8,
                proto: if proto == Proto::Tcp { libc::IPPROTO_TCP } else { libc::IPPROTO_UDP } as u8,
                proto_variant: variant, direction: PF_OUT,
            };
            look.saddr[..4].copy_from_slice(&peer.ip().octets());
            look.daddr[..4].copy_from_slice(&local.ip().octets());
            look.sxport[..2].copy_from_slice(&peer.port().to_be_bytes());
            look.dxport[..2].copy_from_slice(&local.port().to_be_bytes());
            if unsafe { libc::ioctl(pf.as_raw_fd(), DIOCNATLOOK, &mut look as *mut NatLook) } != 0 { return None; }
            let ip = Ipv4Addr::new(look.rdaddr[0], look.rdaddr[1], look.rdaddr[2], look.rdaddr[3]);
            Some(SocketAddrV4::new(ip, u16::from_be_bytes([look.rdxport[0], look.rdxport[1]])))
        })
    }))
}

#[cfg(not(target_os = "macos"))]
pub fn pf_original_destination() -> io::Result<OriginalDestination> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "pf is macOS only"))
}

fn v4(addr: SocketAddr) -> Option<SocketAddrV4> {
    match addr { SocketAddr::V4(a) => Some(a), SocketAddr::V6(_) => None }
}

#[derive(Default)]
struct Open {
    next: u64,
    streams: HashMap<u64, (TcpStream, Option<TcpStream>)>,
}

enum FlowState {
    /// Associating: datagrams meanwhile are dropped (the app resends).
    Pending,
    Ready(Arc<UdpSocket>),
    /// Refused: dropped until then, without asking the proxy again.
    Refused(Instant),
}

struct Flow {
    state: FlowState, target: Target, port: u16, last: Instant, control: Option<TcpStream>,
    /// A local proxy's own datagrams: sent as they are to the real address.
    raw: bool,
}

type Flows = Arc<Mutex<HashMap<(SocketAddrV4, SocketAddrV4), Flow>>>;

pub struct Listener {
    tcp_port: u16,
    udp_port: u16,
    stopped: Arc<AtomicBool>,
    /// Writing a byte here ends the waiting thread (no loopback
    /// connection needed to wake it).
    wake: Option<std::os::fd::OwnedFd>,
    open: Arc<Mutex<Open>>,
    flows: Flows,
    thread: Option<JoinHandle<()>>,
}

fn reset(stream: &TcpStream) {
    // Linger 0: close sends RST, so the app fails at once.
    let _ = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO));
    let _ = stream.shutdown(Shutdown::Both);
}

impl Listener {
    pub fn start(routing: Arc<Routing>, original: OriginalDestination) -> io::Result<Listener> {
        let tcp = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        tcp.set_nonblocking(true)?;
        let tcp_port = tcp.local_addr()?.port();
        let udp = Arc::new(UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?);
        udp.set_nonblocking(true)?;
        let udp_port = udp.local_addr()?.port();
        let (read_end, write_end) = crate::child_io::pipe()?;
        let open = Arc::new(Mutex::new(Open::default()));
        let flows: Flows = Arc::default();
        let stopped = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));
        let thread = std::thread::Builder::new().name("ac-proxy".into()).stack_size(STACK).spawn({
            let (open, flows, stopped) = (open.clone(), flows.clone(), stopped.clone());
            move || {
                let mut buffer = vec![0u8; 65535];
                loop {
                    // Parked until a connection, a datagram or the stop pipe.
                    let mut polled = [
                        libc::pollfd { fd: tcp.as_raw_fd(), events: libc::POLLIN, revents: 0 },
                        libc::pollfd { fd: udp.as_raw_fd(), events: libc::POLLIN, revents: 0 },
                        libc::pollfd { fd: read_end.as_raw_fd(), events: libc::POLLIN, revents: 0 },
                    ];
                    if unsafe { libc::poll(polled.as_mut_ptr(), 3, -1) } < 0 {
                        if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted { continue; }
                        return;
                    }
                    if polled[2].revents != 0 { return; }
                    while let Ok((stream, _)) = crate::child_io::accept(&tcp) {
                        accept(stream, &routing, &original, &open, &active);
                    }
                    while let Ok((n, from)) = udp.recv_from(&mut buffer) {
                        datagram(&buffer[..n], from, &udp, &routing, &original, &flows, &stopped);
                    }
                }
            }
        })?;
        Ok(Listener { tcp_port, udp_port, stopped, wake: Some(write_end), open, flows, thread: Some(thread) })
    }

    pub fn port(&self) -> u16 { self.tcp_port }
    pub fn udp_port(&self) -> u16 { self.udp_port }

    /// Ends the listener and every connection and flow it carries.
    pub fn stop(&mut self) {
        if self.stopped.swap(true, Ordering::AcqRel) { return; }
        if let Some(wake) = self.wake.take() {
            unsafe { libc::write(wake.as_raw_fd(), [1u8].as_ptr() as *const libc::c_void, 1) };
        }
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
        for (_, (client, upstream)) in self.open.lock().unwrap().streams.drain() {
            let _ = client.shutdown(Shutdown::Both);
            if let Some(upstream) = upstream { let _ = upstream.shutdown(Shutdown::Both); }
        }
        // Closing the control connections ends the associations; each
        // flow's thread leaves at its next check.
        for (_, flow) in self.flows.lock().unwrap().drain() {
            if let Some(control) = flow.control { let _ = control.shutdown(Shutdown::Both); }
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) { self.stop(); }
}

// MARK: TCP

fn accept(stream: TcpStream, routing: &Arc<Routing>, original: &OriginalDestination, open: &Arc<Mutex<Open>>, active: &Arc<AtomicUsize>) {
    no_sigpipe(&stream);
    let _ = stream.set_nonblocking(false);
    if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
        active.fetch_sub(1, Ordering::AcqRel);
        routing.failed("网站", "同时经代理的连接太多");
        reset(&stream);
        return;
    }
    let (routing, original, open, active) = (routing.clone(), original.clone(), open.clone(), active.clone());
    let started = std::thread::Builder::new().name("ac-proxy-conn".into()).stack_size(STACK).spawn(move || {
        serve(stream, &routing, &original, &open);
        active.fetch_sub(1, Ordering::AcqRel);
    });
    if started.is_err() { /* the stream was moved and dropped: closed */ }
}

fn serve(client: TcpStream, routing: &Routing, original: &OriginalDestination, open: &Mutex<Open>) {
    let addresses = client.peer_addr().ok().and_then(v4).zip(client.local_addr().ok().and_then(v4));
    let Some(destination) = addresses.and_then(|(peer, local)| original(Proto::Tcp, peer, local)) else {
        // Not a redirected connection (someone connected to the port).
        reset(&client);
        return;
    };
    let (target, server) = match routing.target(*destination.ip()) {
        Ok(target) => target,
        Err((site, reason)) => { routing.failed(&site, &reason); reset(&client); return; }
    };
    // A proxy on this Mac connecting for its own upstream: the ordinary
    // split, never back into the proxy (a loop).
    let local_proxy = addresses.is_some_and(|(peer, _)| routing.from_local_proxy(Proto::Tcp, peer.port()));
    let id = {
        let mut open = open.lock().unwrap();
        open.next += 1;
        let id = open.next;
        if let Ok(copy) = client.try_clone() { open.streams.insert(id, (copy, None)); }
        id
    };
    let forget = || { open.lock().unwrap().streams.remove(&id); };
    let opened = if local_proxy {
        match routing.passthrough(&target) {
            Some(ip) => TcpStream::connect_timeout(&SocketAddr::from((ip, destination.port())), Duration::from_secs(8))
                .map(|stream| { no_sigpipe(&stream); (stream, Vec::new()) })
                .map_err(|e| format!("本机代理自己的连接没能接通（{e}）")),
            None => Err("本机代理自己的连接没有可用的真实地址".to_owned()),
        }
    } else {
        open_through(&server, &target, destination.port())
    };
    let (upstream, early) = match opened {
        Ok(opened) => opened,
        Err(reason) => { routing.failed(&target.label(), &reason); reset(&client); forget(); return; }
    };
    routing.opened();
    if let (Some(entry), Ok(copy)) = (open.lock().unwrap().streams.get_mut(&id), upstream.try_clone()) { entry.1 = Some(copy); }
    let _ = client.set_nodelay(true);
    let mut to_app = &client;
    if !early.is_empty() && to_app.write_all(&early).is_err() { reset(&client); forget(); return; }
    splice(&client, &upstream);
    forget();
}

/// Both directions until both ends are done; one end finishing closes
/// the other's sending side.
fn splice(client: &TcpStream, upstream: &TcpStream) {
    let (Ok(client_read), Ok(upstream_write)) = (client.try_clone(), upstream.try_clone()) else { return };
    let up = std::thread::Builder::new().name("ac-proxy-up".into()).stack_size(STACK).spawn(move || {
        let (mut from, mut to) = (&client_read, &upstream_write);
        let _ = io::copy(&mut from, &mut to);
        let _ = upstream_write.shutdown(Shutdown::Write);
    });
    let (mut from, mut to) = (upstream, client);
    let _ = io::copy(&mut from, &mut to);
    let _ = client.shutdown(Shutdown::Write);
    match up {
        Ok(thread) => { let _ = thread.join(); }
        Err(_) => { let _ = upstream.shutdown(Shutdown::Both); }
    }
}

// MARK: UDP

/// One datagram from an app: to its flow's relay, opening the flow (a
/// SOCKS5 UDP association) on the first one. Never sent another way.
fn datagram(payload: &[u8], from: SocketAddr, udp: &Arc<UdpSocket>, routing: &Arc<Routing>,
            original: &OriginalDestination, flows: &Flows, stopped: &Arc<AtomicBool>) {
    let Some(app) = v4(from) else { return };
    let Some(local) = udp.local_addr().ok().and_then(v4) else { return };
    let Some(destination) = original(Proto::Udp, app, local) else { return };
    let key = (app, destination);
    let now = Instant::now();
    let mut table = flows.lock().unwrap();
    if let Some(flow) = table.get_mut(&key) {
        match &flow.state {
            FlowState::Ready(relay) => {
                flow.last = now;
                if flow.raw { let _ = relay.send(payload); }
                else if let Some(packet) = udp_wrap(&flow.target, flow.port, payload) { let _ = relay.send(&packet); }
                return;
            }
            FlowState::Pending => return,
            FlowState::Refused(until) if now < *until => return,
            FlowState::Refused(_) => { table.remove(&key); }
        }
    }
    let (target, server) = match routing.target(*destination.ip()) {
        Ok(target) => target,
        Err((site, reason)) => { routing.failed(&site, &reason); return; }
    };
    let raw = routing.from_local_proxy(Proto::Udp, app.port());
    if server.kind != Kind::Socks5 && !raw {
        // HTTP CONNECT carries TCP only; the app falls back to TCP.
        return;
    }
    if table.len() >= MAX_FLOWS {
        table.retain(|_, flow| flow.last.elapsed() < UDP_IDLE);
        if table.len() >= MAX_FLOWS { routing.failed(&target.label(), "同时经代理的 UDP 太多"); return; }
    }
    table.insert(key, Flow { state: FlowState::Pending, target: target.clone(), port: destination.port(), last: now, control: None, raw });
    drop(table);
    let first = payload.to_vec();
    let (udp, routing, stopped) = (udp.clone(), routing.clone(), stopped.clone());
    let thread_flows = flows.clone();
    let started = std::thread::Builder::new().name("ac-proxy-udp".into()).stack_size(STACK).spawn(move || {
        let flows = thread_flows;
        let opened = if raw {
            routing.passthrough(&target).ok_or_else(|| "本机代理自己的 UDP 没有可用的真实地址".to_owned())
                .and_then(|ip| UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                    .and_then(|s| s.connect((ip, destination.port())).map(|_| s))
                    .map_err(|e| format!("本机代理自己的 UDP 没能接通（{e}）")))
                .map(|socket| (None, socket))
        } else {
            udp_associate(&server).map(|(control, socket)| (Some(control), socket))
        };
        let (control, relay) = match opened {
            Ok(opened) => opened,
            Err(reason) => {
                routing.failed(&target.label(), &reason);
                if let Some(flow) = flows.lock().unwrap().get_mut(&key) { flow.state = FlowState::Refused(Instant::now() + UDP_RETRY); }
                return;
            }
        };
        let relay = Arc::new(relay);
        let _ = relay.set_read_timeout(Some(UDP_CHECK));
        {
            let mut table = flows.lock().unwrap();
            let Some(flow) = table.get_mut(&key) else { return };
            if stopped.load(Ordering::Acquire) { return; }
            flow.state = FlowState::Ready(relay.clone());
            flow.control = control.as_ref().and_then(|c| c.try_clone().ok());
        }
        routing.opened();
        if raw { let _ = relay.send(&first); }
        else if let Some(packet) = udp_wrap(&target, destination.port(), &first) { let _ = relay.send(&packet); }
        let mut buffer = vec![0u8; 65535];
        loop {
            match relay.recv(&mut buffer) {
                Ok(n) => {
                    let data = if raw { Some(&buffer[..n]) } else { udp_unwrap(&buffer[..n]) };
                    if let Some(data) = data {
                        // pf turns our source back into the address the app used.
                        let _ = udp.send_to(data, app);
                        if let Some(flow) = flows.lock().unwrap().get_mut(&key) { flow.last = Instant::now(); }
                    }
                }
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                Err(_) => break,
            }
            if stopped.load(Ordering::Acquire) { break; }
            let idle = flows.lock().unwrap().get(&key).is_none_or(|flow| flow.last.elapsed() >= UDP_IDLE);
            if idle { break; }
        }
        flows.lock().unwrap().remove(&key);
        drop(control);
    });
    if started.is_err() { flows.lock().unwrap().remove(&key); }
}
