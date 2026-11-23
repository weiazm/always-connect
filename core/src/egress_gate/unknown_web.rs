use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const MAX_ENDPOINTS: usize = 32;
const MAX_INTERNAL_CIDRS: usize = 128;

/// An approved exception only for the exact numeric Web endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct UnknownWebEndpoint {
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Clone, Debug, Default)]
pub struct UnknownWebPolicy {
    active: bool,
    exceptions: HashSet<SocketAddr>,
    internal_cidrs: Vec<(IpAddr, u8)>,
}

impl UnknownWebPolicy {
    pub fn new(active: bool, exceptions: &[UnknownWebEndpoint], internal_cidrs: &[String]) -> Self {
        if !active {
            return Self::default();
        }
        Self {
            active,
            exceptions: exceptions.iter().take(MAX_ENDPOINTS)
                .filter(|endpoint| web_port(endpoint.port))
                .map(|endpoint| SocketAddr::new(endpoint.address, endpoint.port))
                .collect(),
            internal_cidrs: internal_cidrs.iter().take(MAX_INTERNAL_CIDRS)
                .filter_map(|cidr| parse_internal_cidr(cidr))
                .collect(),
        }
    }

    pub(super) fn active(&self) -> bool {
        self.active
    }

    pub(super) fn revoke_exemptions(&mut self) {
        self.exceptions.clear();
        self.internal_cidrs.clear();
    }

    pub(super) fn blocks(&self, destination: SocketAddr) -> bool {
        self.active
            && web_port(destination.port())
            && public_ip(destination.ip())
            && !self.internal_cidrs.iter().any(|&(network, length)| contains(network, length, destination.ip()))
            && !self.exceptions.contains(&destination)
    }
}

fn web_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8443)
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => {
            // Mapped addresses and the well-known translation prefix can
            // denote the same public IPv4 destinations.
            if let Some(ip) = ip.to_ipv4_mapped() {
                return public_v4(ip);
            }
            let segments = ip.segments();
            if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let octets = ip.octets();
                return public_v4(Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]));
            }
            public_v6(ip)
        }
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    !matches!(ip.octets(),
        [0 | 10 | 127 | 224..=255, ..]
        | [100, 64..=127, ..]
        | [169, 254, ..]
        | [172, 16..=31, ..]
        | [192, 168, ..]
        | [192, 0, 2, _]
        | [198, 18 | 19, ..]
        | [198, 51, 100, _]
        | [203, 0, 113, _]
    )
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] & 0xe000 == 0x2000
        && segments[..2] != [0x2001, 0x0db8]
        && (segments[0] != 0x3fff || segments[1] & 0xf000 != 0)
}

fn parse_internal_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (address, length) = cidr.split_once('/')?;
    let address: IpAddr = address.parse().ok()?;
    let length: u8 = length.parse().ok()?;
    let allowed = if address.is_ipv4() { 24..=32 } else { 64..=128 };
    allowed.contains(&length).then_some((address, length))
}

fn contains(network: IpAddr, length: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) =>
            (u32::from(network) ^ u32::from(address)) >> (32 - length) == 0,
        (IpAddr::V6(network), IpAddr::V6(address)) =>
            (u128::from(network) ^ u128::from(address)) >> (128 - length) == 0,
        _ => false,
    }
}

pub(super) fn is_site_name(name: &str) -> bool {
    name.len() <= 253 && name.parse::<IpAddr>().is_err() && name.split('.').all(|label| {
        let bytes = label.as_bytes();
        bytes.len() <= 63
            && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    })
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct UnknownWebCount {
    pub address: IpAddr,
    pub port: u16,
    pub count: u64,
}

#[derive(Default)]
pub(super) struct UnknownWebCounts {
    totals: HashMap<SocketAddr, u64>,
    changed: bool,
}

impl UnknownWebCounts {
    pub(super) fn record(&mut self, endpoint: SocketAddr) {
        if self.totals.len() >= MAX_ENDPOINTS && !self.totals.contains_key(&endpoint) {
            return;
        }
        let count = self.totals.entry(endpoint).or_default();
        *count += 1;
        self.changed = true;
    }

    pub(super) fn snapshot(&mut self) -> Option<Vec<UnknownWebCount>> {
        if !std::mem::take(&mut self.changed) {
            return None;
        }
        Some(self.totals.iter().map(|(endpoint, &count)| UnknownWebCount {
            address: endpoint.ip(),
            port: endpoint.port(),
            count,
        }).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_exclusions_and_narrow_trusted_prefixes_are_the_only_internal_exemptions() {
        let cidrs = ["0.0.0.0/0", "0.0.0.0/1", "::/0", "2000::/3",
            "93.184.216.0/23", "2600:abcd::/63", "93.184.218.0/24", "2600:1000:abcd::/64",
            "not a prefix"].map(str::to_owned);
        let narrow = UnknownWebPolicy::new(true, &[], &cidrs);
        let empty = UnknownWebPolicy::new(true, &[], &[]);
        let endpoint = |ip: &str| SocketAddr::new(ip.parse().unwrap(), 443);
        for internal in ["10.0.1.2", "100.64.0.12", "172.31.9.1", "192.168.1.1", "169.254.0.1",
                         "127.0.0.1", "fd12::1", "fe80::4", "::1", "::ffff:192.168.1.1"] {
            assert!(!empty.blocks(endpoint(internal)));
            assert!(!narrow.blocks(endpoint(internal)));
        }
        for public in ["93.184.216.44", "93.184.219.44", "2600:abcd::1", "2600:1000:abce::1",
                       "::ffff:93.184.216.44", "64:ff9b::5db8:d82c"] {
            assert!(empty.blocks(endpoint(public)));
            assert!(narrow.blocks(endpoint(public)), "{public}");
        }
        for trusted in ["93.184.218.44", "2600:1000:abcd::1"] {
            assert!(empty.blocks(endpoint(trusted)));
            assert!(!narrow.blocks(endpoint(trusted)));
        }
    }

    #[test]
    fn reporting_never_reuses_a_cumulative_endpoint_slot() {
        let mut counts = UnknownWebCounts::default();
        for i in 0..=MAX_ENDPOINTS {
            counts.record(SocketAddr::from(([93, 184, 216, i as u8], 443)));
        }
        assert_eq!(counts.snapshot().unwrap().len(), MAX_ENDPOINTS);
        assert!(counts.snapshot().is_none());
        let first = SocketAddr::from(([93, 184, 216, 0], 443));
        counts.record(first);
        let rows = counts.snapshot().unwrap();
        assert_eq!(rows.iter().find(|row| row.address == first.ip()).unwrap().count, 2);
        assert!(rows.iter().all(|row| row.address != IpAddr::from([93, 184, 216, MAX_ENDPOINTS as u8])));
    }
}
