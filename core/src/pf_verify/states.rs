use super::{diagnostic_lines, readable, valid_name, PfOutput};
use std::collections::BTreeSet;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    InvalidPolicy,
    ReadFailed,
    UnrecognizedState,
    FloatingState,
    UnknownInterface,
    TranslatedState,
    AmbiguousSelector,
    StateChanged,
    DeleteFailed,
    BlockedStateRemains,
}

/// The allowances of the strict blocking rules, with destination port 53
/// denied ahead of every physical-interface exception.
pub struct BlockingPolicy {
    physical: String,
    gateways: BTreeSet<IpAddr>,
    carrier_port: u16,
    carrier_udp: bool,
    lan: Vec<Network>,
}

impl BlockingPolicy {
    pub fn new(
        physical_interface: &str,
        verified_gateways: &[String],
        carrier_port: u16,
        carrier_udp: bool,
        lan_networks: &[String],
    ) -> Result<Self, StateError> {
        let invalid_interface = if physical_interface.is_empty() {
            !verified_gateways.is_empty() || !lan_networks.is_empty()
        } else {
            physical_interface.len() >= 16
                || !valid_name(physical_interface)
                || physical_interface == "all"
                || local_interface(physical_interface)
        };
        if carrier_port == 0 || invalid_interface {
            return Err(StateError::InvalidPolicy);
        }
        Ok(Self {
            physical: physical_interface.to_owned(),
            gateways: verified_gateways
                .iter()
                .map(|value| value.parse())
                .collect::<Result<_, _>>()
                .map_err(|_| StateError::InvalidPolicy)?,
            carrier_port,
            carrier_udp,
            lan: lan_networks
                .iter()
                .map(|value| Network::parse(value))
                .collect::<Option<_>>()
                .ok_or(StateError::InvalidPolicy)?,
        })
    }

    fn preserves(&self, state: &State<'_>) -> Result<bool, StateError> {
        if local_interface(state.interface) {
            return Ok(true);
        }
        if state.interface == "all" {
            return Err(StateError::FloatingState);
        }
        if self.physical != state.interface {
            return Err(StateError::UnknownInterface);
        }
        if state.translated {
            return Err(StateError::TranslatedState);
        }
        Ok(self.allows(state))
    }

    fn allows(&self, state: &State<'_>) -> bool {
        let Endpoint { ip, port } = state.remote;
        let tcp_or_udp = matches!(state.protocol, Protocol::Tcp | Protocol::Udp);
        if tcp_or_udp && port == Some(53) {
            return false;
        }
        let carrier_protocol = state.protocol == Protocol::Tcp
            || (state.protocol == Protocol::Udp && self.carrier_udp);
        if carrier_protocol && port == Some(self.carrier_port) && self.gateways.contains(&ip) {
            return true;
        }
        if self.lan.iter().any(|network| network.contains(ip)) {
            return true;
        }
        match ip {
            IpAddr::V4(address) => {
                state.protocol == Protocol::Udp
                    && ((state.local.port == Some(68) && port == Some(67))
                        || (address.octets() == [224, 0, 0, 251] && port == Some(5353)))
            }
            IpAddr::V6(address) => {
                let link_multicast = address.segments()[0] == 0xff02;
                address.is_unicast_link_local()
                    || (link_multicast && state.protocol == Protocol::Icmp)
                    || (state.protocol == Protocol::Udp
                        && ((address.segments() == [0xff02, 0, 0, 0, 0, 0, 0, 0xfb]
                            && port == Some(5353))
                            || (address.segments() == [0xff02, 0, 0, 0, 0, 0, 1, 2]
                                && port == Some(547)
                                && state.local.port == Some(546)
                                && matches!(state.local.ip, IpAddr::V6(local) if local.is_unicast_link_local()))))
            }
        }
    }
}

struct Network {
    address: IpAddr,
    prefix: u32,
}

impl Network {
    fn parse(value: &str) -> Option<Self> {
        let (address, prefix) = value.split_once('/')?;
        let address: IpAddr = address.parse().ok()?;
        let prefix = prefix.parse().ok()?;
        (prefix <= if address.is_ipv4() { 32 } else { 128 }).then_some(Self { address, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                (u32::from(network) ^ u32::from(address)).leading_zeros() >= self.prefix
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                (u128::from(network) ^ u128::from(address)).leading_zeros() >= self.prefix
            }
            _ => false,
        }
    }
}

fn local_interface(name: &str) -> bool {
    name == "lo0"
        || name
            .strip_prefix("utun")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|c| c.is_ascii_digit()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

impl Protocol {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "tcp" | "6" => Self::Tcp,
            "udp" | "17" => Self::Udp,
            "icmp" | "icmp6" | "ipv6-icmp" | "1" | "58" => Self::Icmp,
            name if valid_name(name) => Self::Other,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Endpoint {
    ip: IpAddr,
    port: Option<u16>,
}

impl Endpoint {
    fn parse(value: &str) -> Option<Self> {
        if let Some((ip, port)) = value.strip_suffix(']').and_then(|v| v.rsplit_once('[')) {
            return Some(Self {
                ip: ipv6(ip)?.into(),
                port: Some(port.parse().ok()?),
            });
        }
        if let Ok(socket) = value.parse::<std::net::SocketAddr>() {
            return Some(Self {
                ip: socket.ip(),
                port: Some(socket.port()),
            });
        }
        let ip = value.parse().ok().or_else(|| ipv6(value).map(IpAddr::V6))?;
        Some(Self { ip, port: None })
    }
}

fn ipv6(value: &str) -> Option<std::net::Ipv6Addr> {
    let address = match value.split_once('%') {
        Some((address, scope)) if valid_name(scope) => address,
        Some(_) => return None,
        None => value,
    };
    address.parse().ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct State<'a> {
    interface: &'a str,
    protocol: Protocol,
    local: Endpoint,
    remote: Endpoint,
    outbound: bool,
    translated: bool,
    id: (u64, u32),
}

impl<'a> State<'a> {
    fn header(line: &'a str) -> Option<Self> {
        let fields: Vec<_> = line.split_whitespace().collect();
        let (interface, protocol, local, arrow, remote, level, translated) = match fields.as_slice()
        {
            [interface, protocol, local, arrow, remote, level] => (
                *interface, *protocol, *local, *arrow, *remote, *level, false,
            ),
            [interface, protocol, local, arrow, translated, second_arrow, remote, level]
                if arrow == second_arrow =>
            {
                Endpoint::parse(translated)?;
                (*interface, *protocol, *local, *arrow, *remote, *level, true)
            }
            _ => return None,
        };
        let outbound = match arrow {
            "->" => true,
            "<-" => false,
            _ => return None,
        };
        let (left, right) = level.split_once(':')?;
        if !valid_name(interface)
            || ![left, right].into_iter().all(|word| {
                !word.is_empty() && word.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
            })
        {
            return None;
        }
        let state = Self {
            interface,
            protocol: Protocol::parse(protocol)?,
            local: Endpoint::parse(local)?,
            remote: Endpoint::parse(remote)?,
            outbound,
            translated,
            id: (0, 0),
        };
        if !translated && state.local.ip.is_ipv4() != state.remote.ip.is_ipv4() {
            return None;
        }
        if matches!(state.protocol, Protocol::Tcp | Protocol::Udp)
            && (state.local.port.is_none() || state.remote.port.is_none())
        {
            return None;
        }
        Some(state)
    }

    fn selector(&self) -> (IpAddr, IpAddr) {
        if self.outbound {
            (self.local.ip, self.remote.ip)
        } else {
            (self.remote.ip, self.local.ip)
        }
    }
}

fn parse_states(text: &str) -> Option<Vec<State<'_>>> {
    let mut states = Vec::new();
    let mut lines = text.lines().peekable();
    let mut ids = BTreeSet::new();
    while let Some(header) = lines.next() {
        if header.trim().is_empty() {
            continue;
        }
        let mut state = State::header(header)?;
        // Darwin -vv prints a TCP sequence line, the age line, and finally
        // the ID/creator pair. Read the identities but never use them as CLI
        // kill selectors: Darwin only supports address selectors.
        if lines
            .peek()
            .is_some_and(|line| line.trim_start().starts_with('['))
        {
            lines.next();
        }
        if !lines.next()?.trim_start().starts_with("age ") {
            return None;
        }
        let mut details = lines.next()?.split_whitespace();
        if details.next()? != "id:" {
            return None;
        }
        let id = details.next()?;
        if details.next()? != "creatorid:" {
            return None;
        }
        let creator = details.next()?;
        if id.len() != 16 || creator.len() != 8 {
            return None;
        }
        if !matches!(details.next(), None | Some("(no-sync)")) || details.next().is_some() {
            return None;
        }
        state.id = (
            u64::from_str_radix(id, 16).ok()?,
            u32::from_str_radix(creator, 16).ok()?,
        );
        if !ids.insert(state.id) {
            return None;
        }
        states.push(state);
    }
    Some(states)
}

fn snapshot<E>(run: &mut impl FnMut(&[&str]) -> Result<PfOutput, E>) -> Result<String, StateError> {
    run(&["-vv", "-s", "states"])
        .ok()
        .and_then(readable)
        .ok_or(StateError::ReadFailed)
}

fn unique_selector(state: &State<'_>, states: &[State<'_>]) -> bool {
    let (source, destination) = state.selector();
    // DIOCKILLSTATES matches the LAN-side tuple. Even a two-endpoint
    // printout can hide a translated external LAN-side address. Exclude
    // every other row whose *visible* LAN-side address could match.
    states
        .iter()
        .filter(|other| other.interface == state.interface)
        .all(|other| {
            other.id == state.id
                || (if other.outbound { source } else { destination }) != other.local.ip
        })
}

fn check_snapshot(policy: &BlockingPolicy, states: &[State<'_>]) -> Result<(), StateError> {
    for state in states {
        if !policy.preserves(state)? {
            return Err(StateError::BlockedStateRemains);
        }
    }
    Ok(())
}

/// Read-only check for diagnostics against the same strict policy.
pub fn check_states<E>(
    policy: &BlockingPolicy,
    mut run: impl FnMut(&[&str]) -> Result<PfOutput, E>,
) -> Result<(), StateError> {
    let raw = snapshot(&mut run)?;
    check_snapshot(
        policy,
        &parse_states(&raw).ok_or(StateError::UnrecognizedState)?,
    )
}

/// Invoke only from NetworkGuard after confirming the installed strict
/// anchor and its call chain. All arguments passed to the runner are fixed
/// tokens, validated interface names, or canonical single-host IPs.
/// A successful result requires a clean readback, including floating states.
pub fn clear_states<E>(
    policy: &BlockingPolicy,
    mut run: impl FnMut(&[&str]) -> Result<PfOutput, E>,
) -> Result<(), StateError> {
    let raw = snapshot(&mut run)?;
    let states = parse_states(&raw).ok_or(StateError::UnrecognizedState)?;
    let mut earlier_error = None;
    let mut attempted = false;
    for state in &states {
        match policy.preserves(state) {
            Ok(true) => continue,
            Err(error) => {
                earlier_error.get_or_insert(error);
                continue;
            }
            Ok(false) => {}
        }
        if !unique_selector(state, &states) {
            earlier_error.get_or_insert(StateError::AmbiguousSelector);
            continue;
        }
        // The list and kill are separate kernel operations. Recheck the
        // same identity immediately before issuing an address-pair kill.
        let current_raw = snapshot(&mut run)?;
        let current = parse_states(&current_raw).ok_or(StateError::UnrecognizedState)?;
        if !current.contains(state) || !unique_selector(state, &current) {
            return Err(StateError::StateChanged);
        }
        let (from, to) = state.selector();
        let output = run(&[
            "-i",
            state.interface,
            "-k",
            &from.to_string(),
            "-k",
            &to.to_string(),
        ])
        .map_err(|_| StateError::DeleteFailed)?;
        let mut lines = diagnostic_lines(&output.stderr);
        if !matches!(
            lines.next(),
            Some(
                "killed 0 states from 1 sources and 1 destinations"
                    | "killed 1 states from 1 sources and 1 destinations"
            )
        ) || lines.next().is_some()
        {
            return Err(StateError::DeleteFailed);
        }
        attempted = true;
    }
    if let Some(error) = earlier_error {
        return Err(error);
    }
    if attempted {
        check_states(policy, run)
    } else {
        Ok(())
    }
}
