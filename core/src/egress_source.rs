//! Allowed VPN egress source addresses for one enabled group.
//!
//! The group owns the saved `exitRangeCheck` and `exitRanges` fields. This
//! module compiles those inputs and creates suggestions without mutating them.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourcePrefix {
    network: IpAddr,
    length: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourcePrefixError {
    InvalidAddress,
    InvalidLength,
    HostBitsSet,
}

impl fmt::Display for SourcePrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidAddress => "invalid exit IP address",
            Self::InvalidLength => "invalid exit prefix length",
            Self::HostBitsSet => "exit prefix has host bits set",
        })
    }
}

impl std::error::Error for SourcePrefixError {}

impl FromStr for SourcePrefix {
    type Err = SourcePrefixError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let (address, length) = value
            .split_once('/')
            .map_or((value, None), |(address, length)| (address, Some(length)));
        let network: IpAddr = address
            .parse()
            .map_err(|_| SourcePrefixError::InvalidAddress)?;
        let width = if network.is_ipv4() { 32 } else { 128 };
        let length = match length {
            Some(text) if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) => {
                text.parse::<u8>()
                    .ok()
                    .filter(|&length| length <= width)
                    .ok_or(SourcePrefixError::InvalidLength)?
            }
            Some(_) => return Err(SourcePrefixError::InvalidLength),
            None => width,
        };
        if network_address(network, length) != network {
            return Err(SourcePrefixError::HostBitsSet);
        }
        Ok(Self { network, length })
    }
}

impl SourcePrefix {
    /// Prefixes only match within the same address family. Mapped IPv6
    /// values therefore cannot authorize native IPv4 addresses, or vice versa.
    pub fn contains(self, address: IpAddr) -> bool {
        address.is_ipv4() == self.network.is_ipv4()
            && network_address(address, self.length) == self.network
    }
}

impl fmt::Display for SourcePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.length)
    }
}

impl Serialize for SourcePrefix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SourcePrefix {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

fn network_address(address: IpAddr, length: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mask = u32::MAX.checked_shl(u32::from(32 - length)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        IpAddr::V6(address) => {
            let mask = u128::MAX.checked_shl(u32::from(128 - length)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceEvidence {
    /// A source IP read from a successful, direct probe of the protected
    /// destination. The probe's server peer address is a different value.
    Direct(IpAddr),
    /// Missing source IP, proxy or third-party evidence, or a probe whose
    /// destination could not be verified.
    Unverified,
}

impl SourceEvidence {
    fn address(self) -> Option<IpAddr> {
        let Self::Direct(address) = self else {
            return None;
        };
        // Classify non-routable values inside mapped addresses too. Return
        // the original family so it still needs its own explicit range.
        let kind = address.to_canonical();
        if kind.is_unspecified() || kind.is_loopback() || kind.is_multicast() {
            return None;
        }
        match kind {
            IpAddr::V4(ip) if ip.is_link_local() || ip.is_broadcast() => None,
            IpAddr::V6(ip) if ip.is_unicast_link_local() => None,
            _ => Some(address),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceDecision {
    Disabled,
    Allowed,
    NoDirectAddress,
    Unrecognized,
}

impl SourceDecision {
    pub fn failure_reason(self) -> Option<&'static str> {
        match self {
            Self::NoDirectAddress => Some("exit-ip-unavailable"),
            Self::Unrecognized => Some("exit-range-mismatch"),
            Self::Disabled | Self::Allowed => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourcePolicy {
    enabled: bool,
    exit_ranges: Vec<SourcePrefix>,
}

impl SourcePolicy {
    /// Compile the group's flat configuration at load or edit. A disabled
    /// check leaves the caller's existing country decision in effect. The
    /// caller must reject malformed enabled ranges instead of committing an
    /// update that would disable or widen protection.
    pub fn from_config(enabled: bool, exit_ranges: &[String]) -> Result<Self, SourcePrefixError> {
        if !enabled {
            return Ok(Self::default());
        }
        let exit_ranges = exit_ranges
            .iter()
            .map(|text| text.parse())
            .collect::<Result<_, _>>()?;
        Ok(Self {
            enabled,
            exit_ranges,
        })
    }

    pub fn evaluate(&self, evidence: SourceEvidence) -> SourceDecision {
        if !self.enabled {
            return SourceDecision::Disabled;
        }
        let Some(address) = evidence.address() else {
            return SourceDecision::NoDirectAddress;
        };
        if self.exit_ranges.iter().any(|range| range.contains(address)) {
            SourceDecision::Allowed
        } else {
            SourceDecision::Unrecognized
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceSuggestion {
    pub address: IpAddr,
    /// A review choice inferred from the address. The only observation is
    /// `address`. The proposed subnet takes effect after explicit consent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_prefix: Option<SourcePrefix>,
}

impl SourceSuggestion {
    pub fn from_evidence(evidence: SourceEvidence, learn_networks: bool) -> Option<Self> {
        let address = evidence.address()?;
        let suggested_prefix = (learn_networks && address.is_ipv4()).then(|| SourcePrefix {
            network: network_address(address, 24),
            length: 24,
        });
        Some(Self {
            address,
            suggested_prefix,
        })
    }
}

#[cfg(test)]
mod tests;
