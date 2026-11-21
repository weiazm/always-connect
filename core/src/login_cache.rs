//! Gateway addresses from established sessions and short-lived TLS preparation.
//!
//! The cache belongs to the background service. Call sites record only the
//! actual peer of a session that passed the engine's existing certificate
//! checks and completed login. Preparation has no path to this cache.

use serde::{Deserialize, Serialize};
use std::ffi::{c_char, CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FILE: &CStr = c"login-gateway-cache.json";
const MAX_GATEWAYS: usize = 64;
const MAX_ADDRESSES: usize = 8;
const MAX_FILE_BYTES: usize = 256 * 1024;
const ADDRESS_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const PROBE_BUDGET: Duration = Duration::from_secs(2);
const PREPARATION_TTL: Duration = Duration::from_secs(60);

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
struct Gateway {
    host: String,
    port: u16,
}

impl Gateway {
    fn new(host: &str, port: u16) -> Option<Self> {
        if port == 0 {
            return None;
        }
        let host = host.strip_suffix('.').unwrap_or(host);
        let literal = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(host);
        if let Ok(ip) = literal.parse::<IpAddr>() {
            return Some(Self {
                host: ip.to_string(),
                port,
            });
        }
        let valid_name = host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.chars().all(|ch| {
                        ch.is_ascii_alphanumeric()
                            || matches!(ch, '-' | '_')
                            || (!ch.is_ascii() && !ch.is_whitespace() && !ch.is_control())
                    })
            });
        valid_name.then(|| Self {
            host: host.to_lowercase(),
            port,
        })
    }
}

fn parse_address(text: &str) -> Option<IpAddr> {
    usable_address(text.parse().ok()?)
}

fn usable_address(address: IpAddr) -> Option<IpAddr> {
    // The rule and the socket must see the same family. A link-local IPv6
    // address would also need a scope, which this representation cannot pin.
    let address = address.to_canonical();
    match address {
        IpAddr::V4(ip) if ip.is_broadcast() => None,
        IpAddr::V6(ip) if ip.is_unicast_link_local() => None,
        ip if ip.is_unspecified() || ip.is_multicast() => None,
        ip => Some(ip),
    }
}

#[derive(Deserialize, Serialize)]
struct Peer {
    address: IpAddr,
    used_at: u64,
}

impl Peer {
    fn fresh(&self, now: u64) -> bool {
        now.checked_sub(self.used_at)
            .is_some_and(|age| age < ADDRESS_TTL.as_secs())
    }
}

#[derive(Deserialize, Serialize)]
struct GatewayPeers {
    gateway: Gateway,
    peers: Vec<Peer>,
}

#[derive(Deserialize, Serialize)]
struct Cache {
    version: u8,
    gateways: Vec<GatewayPeers>,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            version: 1,
            gateways: Vec::new(),
        }
    }
}

impl Cache {
    fn addresses(&self, gateway: &Gateway, now: u64) -> Vec<String> {
        self.gateways
            .iter()
            .find(|entry| entry.gateway == *gateway)
            .into_iter()
            .flat_map(|entry| &entry.peers)
            .filter(|peer| peer.fresh(now))
            .map(|peer| peer.address.to_string())
            .collect()
    }

    fn record(&mut self, gateway: Gateway, address: IpAddr, now: u64) {
        for entry in &mut self.gateways {
            entry.peers.retain(|peer| peer.fresh(now));
        }
        self.gateways.retain(|entry| !entry.peers.is_empty());
        let mut peers = self
            .gateways
            .iter()
            .position(|entry| entry.gateway == gateway)
            .map(|index| self.gateways.remove(index).peers)
            .unwrap_or_default();
        peers.retain(|peer| peer.address != address);
        peers.insert(
            0,
            Peer {
                address,
                used_at: now,
            },
        );
        peers.truncate(MAX_ADDRESSES);
        self.gateways.insert(0, GatewayPeers { gateway, peers });
        self.gateways.truncate(MAX_GATEWAYS);
    }

    fn valid(&self) -> bool {
        self.version == 1
            && self.gateways.len() <= MAX_GATEWAYS
            && self.gateways.iter().enumerate().all(|(index, entry)| {
                Gateway::new(&entry.gateway.host, entry.gateway.port).as_ref()
                    == Some(&entry.gateway)
                    && !self.gateways[..index]
                        .iter()
                        .any(|earlier| earlier.gateway == entry.gateway)
                    && entry.peers.len() <= MAX_ADDRESSES
                    && entry.peers.iter().enumerate().all(|(index, peer)| {
                        usable_address(peer.address) == Some(peer.address)
                            && !entry.peers[..index]
                                .iter()
                                .any(|earlier| earlier.address == peer.address)
                    })
            })
    }
}

/// Ordered addresses for the configured TLS host and carrier port. A missing,
/// inaccessible or invalid cache is a miss. This function never resolves DNS.
pub fn lookup(dir: &Path, host: &str, port: u16) -> Vec<String> {
    let Some(gateway) = Gateway::new(host, port) else {
        return Vec::new();
    };
    let Ok(now) = unix_time() else {
        return Vec::new();
    };
    open_private_directory(dir)
        .and_then(|dir| read_cache(&dir))
        .map(|cache| cache.addresses(&gateway, now))
        .unwrap_or_default()
}

/// Persist the actual peer after an authenticated session establishes. The
/// caller supplies the relay's upstream peer, never its loopback endpoint.
/// `dir` is the service's existing trusted support directory, not XPC input.
pub fn remember(dir: &Path, host: &str, port: u16, address: &str) -> io::Result<()> {
    let gateway = Gateway::new(host, port).ok_or(io::ErrorKind::InvalidInput)?;
    let address = parse_address(address).ok_or(io::ErrorKind::InvalidInput)?;
    let dir = open_private_directory(dir)?;
    // Serialize read/modify/write across callers without adding a lock file.
    // Readers see either complete version via renameat and need no lock.
    loop {
        if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX) } == 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    let mut cache = match read_cache(&dir) {
        Ok(cache) => cache,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::InvalidData
            ) =>
        {
            Cache::default()
        }
        Err(error) => return Err(error),
    };
    cache.record(gateway, address, unix_time()?);
    write_cache(&dir, &cache)
}

fn unix_time() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|age| age.as_secs())
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

fn open_private_directory(path: &Path) -> io::Result<File> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = dir.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(dir)
}

fn open_at(dir: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_cache(dir: &File) -> io::Result<Cache> {
    let file = open_at(dir, FILE, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() > 1
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut bytes = Vec::new();
    file.take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let cache: Cache = serde_json::from_slice(&bytes).map_err(|_| io::ErrorKind::InvalidData)?;
    if !cache.valid() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(cache)
}

fn temporary_name() -> io::Result<CString> {
    let mut random = [0_u8; 8];
    if unsafe { libc::getentropy(random.as_mut_ptr().cast(), random.len()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(CString::new(format!(
        ".login-gateway-cache.{:016x}",
        u64::from_ne_bytes(random)
    ))
    .unwrap())
}

fn write_cache(dir: &File, cache: &Cache) -> io::Result<()> {
    let bytes = serde_json::to_vec(cache)?;
    let name = temporary_name()?;
    let mut file = open_at(dir, &name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
    let fd = dir.as_raw_fd();
    let result = file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            if unsafe { libc::renameat(fd, name.as_ptr(), fd, FILE.as_ptr()) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    if result.is_err() {
        unsafe { libc::unlinkat(fd, name.as_ptr(), 0) };
    }
    result
}

/// A single selected gateway can be prepared while the owner has confirmed
/// direct networking and has no connection intent. Its TLS result applies
/// only to that host and port and has no path to the disk cache.
#[derive(Default)]
struct Preparation {
    sequence: u64,
    state: PreparationState,
}

#[derive(Default)]
enum PreparationState {
    #[default]
    Suspended,
    Direct,
    Checking {
        request: u64,
        gateway: Gateway,
        deadline: Instant,
    },
    Ready {
        gateway: Gateway,
        result: Option<PreparedGateway>,
        expires: Instant,
        verified_at: SystemTime,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedGateway {
    Address(IpAddr),
    CertificateRejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
enum PreparationStatus {
    Idle = 0,
    Preparing = 1,
    Ready = 2,
    CertificateRejected = 3,
    Unavailable = 4,
}

impl Preparation {
    fn confirm_direct(&mut self) {
        if matches!(self.state, PreparationState::Suspended) {
            self.state = PreparationState::Direct;
        }
    }

    fn begin(&mut self, gateway: Gateway, now: Instant) -> Option<u64> {
        match &self.state {
            PreparationState::Suspended => return None,
            PreparationState::Checking {
                gateway: active,
                deadline,
                ..
            } if *active == gateway && now < *deadline => return None,
            PreparationState::Ready {
                gateway: active,
                expires,
                verified_at,
                result: Some(PreparedGateway::Address(_)),
            } if *active == gateway && preparation_fresh(now, *expires, *verified_at) => {
                return None
            }
            _ => {}
        }
        self.sequence = self.sequence.checked_add(1)?;
        self.state = PreparationState::Checking {
            request: self.sequence,
            gateway,
            deadline: now + PROBE_BUDGET,
        };
        Some(self.sequence)
    }

    fn finish(&mut self, request: u64, result: Option<PreparedGateway>, now: Instant) {
        if !matches!(&self.state, PreparationState::Checking { request: active, .. } if *active == request)
        {
            return;
        }
        let previous = std::mem::replace(&mut self.state, PreparationState::Direct);
        if let PreparationState::Checking {
            gateway, deadline, ..
        } = previous
        {
            self.state = PreparationState::Ready {
                gateway,
                result: result.filter(|_| now < deadline),
                expires: now + PREPARATION_TTL,
                verified_at: SystemTime::now(),
            };
        }
    }

    fn status(&self, target: &Gateway, now: Instant) -> PreparationStatus {
        match &self.state {
            PreparationState::Checking {
                gateway, deadline, ..
            } if gateway == target => {
                if now < *deadline {
                    PreparationStatus::Preparing
                } else {
                    PreparationStatus::Unavailable
                }
            }
            PreparationState::Ready {
                gateway,
                result,
                expires,
                verified_at,
            } if gateway == target && preparation_fresh(now, *expires, *verified_at) => {
                match result {
                    Some(PreparedGateway::Address(_)) => PreparationStatus::Ready,
                    Some(PreparedGateway::CertificateRejected) => {
                        PreparationStatus::CertificateRejected
                    }
                    None => PreparationStatus::Unavailable,
                }
            }
            _ => PreparationStatus::Idle,
        }
    }

    fn take_for_intent(
        &mut self,
        target: Option<&Gateway>,
        now: Instant,
    ) -> Option<PreparedGateway> {
        match std::mem::take(&mut self.state) {
            PreparationState::Ready {
                gateway,
                result,
                expires,
                verified_at,
            } if Some(&gateway) == target && preparation_fresh(now, expires, verified_at) => result,
            _ => None,
        }
    }
}

fn preparation_fresh(now: Instant, expires: Instant, verified_at: SystemTime) -> bool {
    // Some platforms' monotonic Instant excludes sleep. Check wall time too
    // so a preparation result cannot be used after a long suspension.
    now < expires && verified_at.elapsed().is_ok_and(|age| age < PREPARATION_TTL)
}

// Swift calls these on a single serial queue per preparation instance.
// Strings are borrowed only for the call. Returned strings use ac_string_free.
mod bridge;

#[cfg(test)]
mod tests;
