//! An on-demand snapshot for the add-website form. It owns no policy state.

use super::{
    build_request, probe_once, valid_host, EgressConfig, ProbeHook, ProbeMethod, PRESET_TRACE,
};
use serde::Serialize;
use std::collections::HashSet;
use std::io::Read;
use std::net::IpAddr;
use std::thread;
use std::time::{Duration, Instant};

const MAX_ADDRESSES: usize = 8;
const TOTAL_BUDGET: Duration = Duration::from_millis(2400);
const DNS_BUDGET: Duration = Duration::from_millis(600);

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum Status {
    Ok,
    Unsupported,
    Unavailable,
    Invalid,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AddressResult {
    address: IpAddr,
    #[serde(rename = "exitIP", skip_serializing_if = "Option::is_none")]
    exit_ip: Option<IpAddr>,
    method: String,
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Summary {
    host: String,
    method: String,
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
    resolved_address_count: usize,
    probed_address_count: usize,
    truncated: bool,
    coverage_incomplete: bool,
    results: Vec<AddressResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_id: Option<String>,
}

pub(crate) struct SetupReceipt {
    id: String,
    issued: std::time::SystemTime,
    host: String,
    method: ProbeMethod,
    exits: Vec<(String, IpAddr)>,
}

impl SetupReceipt {
    pub(crate) fn is_current(&self, id: &str) -> bool {
        self.id == id && self.issued.elapsed().is_ok_and(|age| age < Duration::from_secs(300))
    }

    pub(crate) fn approves(&self, old: &EgressConfig, new: &EgressConfig, id: u32) -> bool {
        if !new.valid() || !new.active() || old.methods != new.methods {
            return false;
        }
        let old_other: Vec<_> = old.groups.iter().filter(|g|g.id!=id).collect();
        let new_other: Vec<_> = new.groups.iter().filter(|g|g.id!=id).collect();
        if old_other.len()!=new_other.len() || !old_other.into_iter().zip(new_other).all(|(before,after)| {
            if before==after {return true}
            // Starting a rule may leave legacy groups, formerly under an off master switch, disabled.
            let mut inert=before.clone();
            inert.enabled=false;
            !old.enabled && inert==*after
        }) { return false; }
        let Some(group) = new.group(id).filter(|g|g.enabled && g.exit_range_check && !g.exit_ranges.is_empty()) else { return false };
        if !group.members.iter().any(|m| m.method.as_deref()==Some(&self.method.id) && super::pattern_matches(&m.pattern,&self.host))
            || new.method(&self.method.id).as_ref()!=Some(&self.method) { return false; }
        let old_ranges = old.group(id).filter(|g|g.exit_range_check).map(|g|g.exit_ranges.as_slice()).unwrap_or_default();
        let supports = |range: &str| self.exits.iter().any(|(country,ip)|
            group.expect.iter().any(|c| c.eq_ignore_ascii_case(country)) && super::approvable_source(range,*ip));
        group.exit_ranges.iter().all(|r| old_ranges.contains(r) || supports(r))
            && group.exit_ranges.iter().any(|r| supports(r))
    }
}

impl Summary {
    pub(crate) fn issue_receipt(&mut self, method: &ProbeMethod) -> Option<SetupReceipt> {
        if self.status != Status::Ok || !method.is_direct() { return None; }
        let exits: Vec<_> = self.results.iter().filter(|r|r.status==Status::Ok)
            .filter_map(|r| Some((r.country.clone()?,r.exit_ip?))).collect();
        if exits.is_empty() { return None; }
        let mut bytes = [0u8; 16];
        if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(),bytes.len()) } != 0 { return None; }
        let id = format!("{:032x}",u128::from_be_bytes(bytes));
        self.proof_id = Some(id.clone());
        Some(SetupReceipt { id, issued:std::time::SystemTime::now(), host:self.host.clone(), method:method.clone(), exits })
    }

    pub(crate) fn request(host: &str, method: &str) -> Self {
        let host = host.strip_suffix('.').unwrap_or(host);
        let mut summary = Self {
            host: String::new(),
            method: if method.is_empty() {
                PRESET_TRACE.into()
            } else {
                method.into()
            },
            status: Status::Unavailable,
            error: Some("tunnelUnavailable"),
            resolved_address_count: 0,
            probed_address_count: 0,
            truncated: false,
            coverage_incomplete: true,
            results: Vec::new(),
            proof_id: None,
        };
        if !valid_host(host) || host.ends_with('.') || host.parse::<IpAddr>().is_ok() {
            summary.status = Status::Invalid;
            summary.error = Some("invalidHost");
        } else {
            summary.host = host.to_ascii_lowercase();
        }
        summary
    }

    pub(crate) fn method(&mut self, config: Option<&EgressConfig>) -> Option<ProbeMethod> {
        if self.status == Status::Invalid {
            return None;
        }
        let default = EgressConfig::default();
        let selected = config
            .unwrap_or(&default)
            .method(&self.method)
            .filter(|method| {
                method.is_direct()
                    && build_request(method, &self.host).is_ok_and(|(name, _, _)| name == self.host)
            });
        if selected.is_none() {
            self.status = Status::Invalid;
            self.error = Some("invalidMethod");
        }
        selected
    }

    pub(crate) fn probe(
        mut self,
        method: &ProbeMethod,
        hook: &ProbeHook,
        marker: &str,
        interface: &str,
        query: impl Fn(&[u8], Instant) -> Option<Vec<u8>> + Sync,
        still_current: impl Fn() -> bool,
    ) -> Self {
        let start = Instant::now();
        let deadline = start + TOTAL_BUDGET;
        let (v4, v6) = self.resolve(&query, start + DNS_BUDGET);
        if !still_current() {
            return self;
        }
        let mut seen = HashSet::new();
        let mut addresses = Vec::new();
        let mut v4_iter = v4.iter().flatten();
        let mut v6_iter = v6.iter().flatten();
        // Keep each family's DNS order and sample both when DNS returns both.
        let mut omitted = false;
        loop {
            let pair = [v4_iter.next(), v6_iter.next()];
            if pair.iter().all(|entry| entry.is_none()) {
                break;
            }
            for address in pair.into_iter().flatten().map(|ip| ip.to_canonical()) {
                if seen.insert(address) {
                    if usable_destination(address) {
                        addresses.push(address);
                    } else {
                        omitted = true;
                    }
                }
            }
        }
        self.truncated = addresses.len() > MAX_ADDRESSES;
        addresses.truncate(MAX_ADDRESSES);
        self.coverage_incomplete = self.truncated || omitted || v4.is_none() || v6.is_none();
        self.resolved_address_count = seen.len();
        if addresses.is_empty() {
            self.error = Some(if self.coverage_incomplete {
                "dnsUnavailable"
            } else {
                "noAddresses"
            });
            return self;
        }

        // The setup result needs a confirmed numeric peer. Keep that stricter
        // check local to this path, including for alternate platform hooks.
        let platform = hook.clone();
        let matching_peer: ProbeHook = std::sync::Arc::new(move |request, peer| {
            let bytes = platform(request, peer)?;
            (*peer == request.connect_ip && bytes.len() <= 65_536).then_some(bytes)
        });
        let results = thread::scope(|scope| {
            let host = self.host.as_str();
            let matching_peer = &matching_peer;
            let workers: Vec<_> = addresses
                .into_iter()
                .map(|address| {
                    let worker = thread::Builder::new().spawn_scoped(scope, move || {
                        let timeout_ms = deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis() as u64;
                        if timeout_ms == 0 {
                            return unavailable_address(address, method);
                        }
                        let (observation, received) = probe_once(
                            matching_peer,
                            method,
                            host,
                            marker,
                            interface,
                            Some(address),
                            "direct",
                            timeout_ms,
                        );
                        if Instant::now() > deadline {
                            return unavailable_address(address, method);
                        }
                        let (status, error) = match (&observation.country, received) {
                            (Some(_), true) => (Status::Ok, None),
                            (None, true) => (Status::Unsupported, Some("noCountry")),
                            _ => (Status::Unavailable, Some("probeUnavailable")),
                        };
                        AddressResult {
                            address,
                            exit_ip: observation.ip.as_deref().and_then(|ip| ip.parse().ok()),
                            method: method.id.clone(),
                            status,
                            error,
                            country: observation.country,
                        }
                    });
                    (address, worker)
                })
                .collect();
            workers
                .into_iter()
                .map(|(address, worker)| {
                    worker
                        .ok()
                        .and_then(|worker| worker.join().ok())
                        .unwrap_or_else(|| unavailable_address(address, method))
                })
                .collect::<Vec<_>>()
        });
        if !still_current() {
            return Self::request(&self.host, &self.method);
        }
        (self.status, self.error) = if results.iter().any(|row| row.status == Status::Ok) {
            (Status::Ok, None)
        } else if results.iter().all(|row| row.status == Status::Unsupported) {
            (Status::Unsupported, Some("noCountry"))
        } else {
            (Status::Unavailable, Some("probeUnavailable"))
        };
        self.probed_address_count = results.len();
        self.results = results;
        self
    }

    fn resolve(
        &self,
        query: &(impl Fn(&[u8], Instant) -> Option<Vec<u8>> + Sync),
        deadline: Instant,
    ) -> (Option<Vec<IpAddr>>, Option<Vec<IpAddr>>) {
        let resolve = |kind| {
            let mut request = crate::on_demand::dns_query(&self.host)?;
            let mut id = [0; 2];
            std::fs::File::open("/dev/urandom")
                .ok()?
                .read_exact(&mut id)
                .ok()?;
            request[..2].copy_from_slice(&id);
            let qtype = request.len() - 3;
            request[qtype] = kind;
            crate::on_demand::dns_addresses(&query(&request, deadline)?, &request)?
                .iter()
                .map(|ip| ip.parse().ok())
                .collect()
        };
        thread::scope(|scope| {
            let v6 = thread::Builder::new().spawn_scoped(scope, || resolve(28));
            let v4 = resolve(1);
            (v4, v6.ok().and_then(|worker| worker.join().ok()).flatten())
        })
    }
}

fn usable_destination(address: IpAddr) -> bool {
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return false;
    }
    match address {
        IpAddr::V4(ip) => !ip.is_link_local() && !ip.is_broadcast(),
        IpAddr::V6(ip) => !ip.is_unicast_link_local(),
    }
}

fn unavailable_address(address: IpAddr, method: &ProbeMethod) -> AddressResult {
    AddressResult {
        address,
        exit_ip: None,
        method: method.id.clone(),
        status: Status::Unavailable,
        country: None,
        error: Some("probeUnavailable"),
    }
}

#[cfg(test)]
mod tests;
