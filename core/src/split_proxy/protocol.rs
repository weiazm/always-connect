//! The proxy protocols, client side: SOCKS5 (RFC 1928) CONNECT and UDP
//! ASSOCIATE with username/password (RFC 1929), and HTTP CONNECT with
//! Basic authentication. Every step has a timeout and a plain reason.

use super::{is_fake, Kind, Server, Target};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn read_exact(stream: &mut TcpStream, bytes: &mut [u8]) -> Result<(), String> {
    stream.read_exact(bytes).map_err(|e| match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => "代理没有回应（超时）".to_owned(),
        io::ErrorKind::UnexpectedEof => "代理关闭了连接".to_owned(),
        _ => format!("与代理通信出错（{e}）"),
    })
}

fn write_all(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), String> {
    stream.write_all(bytes).map_err(|e| format!("与代理通信出错（{e}）"))
}

/// A reset peer must cost one connection, never the service (SIGPIPE).
pub(super) fn no_sigpipe(stream: &TcpStream) {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let _ = socket2::SockRef::from(stream).set_nosigpipe(true);
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let _ = stream;
}

/// SOCKS5 address: ATYP, address, port.
fn socks_address(target: &Target, port: u16) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    match target {
        Target::Name(name) => {
            if name.is_empty() || name.len() > 255 { return Err("域名太长".into()); }
            out.push(3);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
        Target::Ip(ip) => { out.push(1); out.extend_from_slice(&ip.octets()); }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// Method negotiation and, when the proxy asks for it, RFC 1929.
fn socks5_hello(stream: &mut TcpStream, auth: Option<&(String, String)>) -> Result<(), String> {
    write_all(stream, if auth.is_some() { &[5, 2, 0, 2] } else { &[5, 1, 0] })?;
    let mut choice = [0u8; 2];
    read_exact(stream, &mut choice)?;
    if choice[0] != 5 { return Err("对方不是 SOCKS5 代理".into()); }
    match (choice[1], auth) {
        (0, _) => Ok(()),
        (2, Some((user, password))) => {
            let mut request = vec![1, user.len() as u8];
            request.extend_from_slice(user.as_bytes());
            request.push(password.len() as u8);
            request.extend_from_slice(password.as_bytes());
            write_all(stream, &request)?;
            let mut status = [0u8; 2];
            read_exact(stream, &mut status)?;
            if status[1] == 0 { Ok(()) } else { Err("代理拒绝了用户名或密码".into()) }
        }
        (0xff, None) | (2, None) => Err("代理要求用户名密码，请在「代理」页填写".into()),
        (0xff, Some(_)) => Err("代理不接受用户名密码这种认证方式".into()),
        _ => Err("代理要求不支持的认证方式".into()),
    }
}

/// One SOCKS5 request; the proxy's bound address on success.
fn socks5_request(stream: &mut TcpStream, command: u8, target: &Target, port: u16) -> Result<Option<SocketAddr>, String> {
    let mut request = vec![5, command, 0];
    request.extend(socks_address(target, port)?);
    write_all(stream, &request)?;
    let mut head = [0u8; 4];
    read_exact(stream, &mut head)?;
    if head[0] != 5 { return Err("对方不是 SOCKS5 代理".into()); }
    if head[1] != 0 {
        return Err(match head[1] {
            2 => "代理的规则不允许这个连接",
            3 => "代理那边网络不可达",
            4 => "代理那边找不到这个网站",
            5 => "网站拒绝了代理的连接",
            6 => "代理那边连接超时",
            7 if command == 3 => "代理不支持 UDP 转发",
            7 | 8 => "代理不支持这种请求",
            _ => "代理报告连接失败",
        }.into());
    }
    Ok(match head[3] {
        1 => {
            let mut b = [0u8; 6];
            read_exact(stream, &mut b)?;
            Some(SocketAddr::from((Ipv4Addr::new(b[0], b[1], b[2], b[3]), u16::from_be_bytes([b[4], b[5]]))))
        }
        4 => {
            let mut b = [0u8; 18];
            read_exact(stream, &mut b)?;
            let ip: [u8; 16] = b[..16].try_into().unwrap();
            Some(SocketAddr::from((Ipv6Addr::from(ip), u16::from_be_bytes([b[16], b[17]]))))
        }
        3 => {
            let mut n = [0u8; 1];
            read_exact(stream, &mut n)?;
            let mut skip = vec![0u8; n[0] as usize + 2];
            read_exact(stream, &mut skip)?;
            None
        }
        _ => return Err("代理的答复格式不对".into()),
    })
}

/// SOCKS5 CONNECT on a connected stream.
pub fn socks5_connect(stream: &mut TcpStream, auth: Option<&(String, String)>, target: &Target, port: u16) -> Result<(), String> {
    socks5_hello(stream, auth)?;
    socks5_request(stream, 1, target, port).map(|_| ())
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8) | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() { out.push(TABLE[(n >> (18 - 6 * i) & 63) as usize] as char); } else { out.push('='); }
        }
    }
    out
}

/// HTTP CONNECT. Returns bytes the proxy sent after its header (already
/// the site's data).
pub fn http_connect(stream: &mut TcpStream, auth: Option<&(String, String)>, target: &Target, port: u16) -> Result<Vec<u8>, String> {
    let authority = format!("{}:{port}", target.label());
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n");
    if let Some((user, password)) = auth {
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", base64(format!("{user}:{password}").as_bytes())));
    }
    request.push_str("\r\n");
    write_all(stream, request.as_bytes())?;
    let mut buffer = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    let end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") { break at + 4; }
        if buffer.len() > 16 * 1024 { return Err("代理的答复头太长".into()); }
        let n = stream.read(&mut chunk).map_err(|e| match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => "代理没有回应（超时）".to_owned(),
            _ => format!("与代理通信出错（{e}）"),
        })?;
        if n == 0 { return Err("代理关闭了连接".into()); }
        buffer.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buffer[..end]);
    let mut parts = head.lines().next().unwrap_or("").split_whitespace();
    let code = match (parts.next(), parts.next().and_then(|c| c.parse::<u16>().ok())) {
        (Some(v), Some(code)) if v.starts_with("HTTP/") => code,
        _ => return Err("对方不是 HTTP 代理".into()),
    };
    match code {
        200..=299 => Ok(buffer[end..].to_vec()),
        407 if auth.is_some() => Err("代理拒绝了用户名或密码（407）".into()),
        407 => Err("代理要求用户名密码，请在「代理」页填写".into()),
        403 => Err("代理拒绝了这个连接（403）".into()),
        _ => Err(format!("代理拒绝了这个连接（{code}）")),
    }
}

/// Connect to the proxy itself, through the ordinary system path.
fn connect_proxy(server: &Server) -> Result<TcpStream, String> {
    let addresses: Vec<SocketAddr> = (server.host.as_str(), server.port).to_socket_addrs()
        .map_err(|_| format!("解析不了代理地址 {}", server.host))?.collect();
    if addresses.iter().any(|a| matches!(a, SocketAddr::V4(v4) if is_fake(*v4.ip()))) {
        return Err("代理地址本身命中了代理规则，请把它从规则里去掉".into());
    }
    let mut last = format!("连不上代理 {}", server.label());
    for address in addresses {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => {
                no_sigpipe(&stream);
                let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
                let _ = stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
                return Ok(stream);
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => last = format!("连接代理 {} 超时", server.label()),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => last = format!("代理 {} 拒绝连接（没有在运行？）", server.label()),
            Err(_) => {}
        }
    }
    Err(last)
}

/// Open `target:port` through `server`. Bytes already read past the
/// proxy's answer come back with the stream.
pub fn open_through(server: &Server, target: &Target, port: u16) -> Result<(TcpStream, Vec<u8>), String> {
    let mut stream = connect_proxy(server)?;
    let early = match server.kind {
        Kind::Socks5 => socks5_connect(&mut stream, server.auth.as_ref(), target, port).map(|_| Vec::new()),
        Kind::Http => http_connect(&mut stream, server.auth.as_ref(), target, port),
    }?;
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);
    let _ = stream.set_nodelay(true);
    Ok((stream, early))
}

/// SOCKS5 UDP ASSOCIATE: the control connection (the association lives
/// as long as it does) and a socket connected to the proxy's relay. A
/// relay given as 0.0.0.0 / :: (common) means the proxy's own address.
pub fn udp_associate(server: &Server) -> Result<(TcpStream, UdpSocket), String> {
    if server.kind != Kind::Socks5 { return Err("HTTP 代理不能转发 UDP".into()); }
    let mut control = connect_proxy(server)?;
    socks5_hello(&mut control, server.auth.as_ref())?;
    let bound = socks5_request(&mut control, 3, &Target::Ip(Ipv4Addr::UNSPECIFIED), 0)?;
    let proxy_ip = control.peer_addr().map_err(|e| format!("与代理通信出错（{e}）"))?.ip();
    let relay = match bound {
        Some(addr) if !addr.ip().is_unspecified() => addr,
        Some(addr) => SocketAddr::new(proxy_ip, addr.port()),
        None => return Err("代理给的 UDP 中继地址是域名（暂不支持）".into()),
    };
    if matches!(relay.ip(), IpAddr::V4(v4) if is_fake(v4)) { return Err("代理的 UDP 中继地址命中了代理规则".into()); }
    let local: SocketAddr = if relay.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
    let socket = UdpSocket::bind(local).and_then(|s| s.connect(relay).map(|_| s))
        .map_err(|e| format!("连不上代理的 UDP 中继（{e}）"))?;
    let _ = control.set_read_timeout(None);
    let _ = control.set_write_timeout(None);
    Ok((control, socket))
}

/// A datagram for the relay: header (RSV, FRAG 0, address) + payload.
pub fn udp_wrap(target: &Target, port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0, 0, 0];
    out.extend(socks_address(target, port).ok()?);
    out.extend_from_slice(payload);
    Some(out)
}

/// The payload of a datagram from the relay; None for fragments and
/// malformed headers.
pub fn udp_unwrap(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 { return None; }
    let header = match packet[3] {
        1 => 4 + 4 + 2,
        4 => 4 + 16 + 2,
        3 => 4 + 1 + *packet.get(4)? as usize + 2,
        _ => return None,
    };
    packet.get(header..)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_reference_vectors() {
        for (plain, encoded) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy"), ("user:pa ss", "dXNlcjpwYSBzcw==")] {
            assert_eq!(base64(plain.as_bytes()), encoded);
        }
    }

    #[test]
    fn udp_headers_round_trip() {
        let named = udp_wrap(&Target::Name("site.example".into()), 443, b"quic").unwrap();
        assert_eq!(&named[..5], &[0, 0, 0, 3, 12]);
        assert_eq!(udp_unwrap(&named), Some(&b"quic"[..]));
        let by_ip = udp_wrap(&Target::Ip(Ipv4Addr::new(203, 0, 113, 7)), 53, b"q").unwrap();
        assert_eq!(by_ip, vec![0, 0, 0, 1, 203, 0, 113, 7, 0, 53, b'q']);
        assert_eq!(udp_unwrap(&by_ip), Some(&b"q"[..]));
        let mut fragment = by_ip.clone();
        fragment[2] = 1;
        assert_eq!(udp_unwrap(&fragment), None, "fragments are dropped");
        assert_eq!(udp_unwrap(&[0, 0, 0, 3, 200]), None);
    }
}
