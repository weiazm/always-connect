use super::*;

const MAX_FAILED_TARGETS: usize = 8;

#[derive(Clone, PartialEq)]
pub(super) struct Target {
    pub host: String,
    pub method: ProbeMethod,
    pub peer: Option<(IpAddr, u16)>,
    borrowed: bool,
    named_flow: bool,
    alternative: Option<(String, ProbeMethod)>,
}

impl Target {
    pub fn direct_flow(&self) -> bool {
        self.named_flow
    }

    fn evidence(&self) -> &'static str {
        if self.borrowed {
            "proxy"
        } else if self.named_flow {
            "direct"
        } else {
            "member"
        }
    }

    fn unconfirmed(&self, reason: &str) -> Observation {
        Observation {
            host: self.host.clone(),
            method: self.method.id.clone(),
            peer_address: self.peer.map(|p| p.0),
            evidence: Some(self.evidence().into()),
            error: Some(reason.into()),
            ..Default::default()
        }
    }

    pub fn observe(&self, hook: &ProbeHook, marker: &str, iface: &str) -> Observation {
        let deadline = std::time::Instant::now() + Duration::from_millis(2400);
        let ip = self.peer.map(|p| p.0);
        let (observed, received) = probe_once(
            hook,
            &self.method,
            &self.host,
            marker,
            iface,
            ip,
            self.evidence(),
            2400,
        );
        let remaining = deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis() as u64;
        if !received && remaining > 0 {
            if let Some((name, method)) = &self.alternative {
                return probe_once(hook, method, name, marker, iface, ip, "proxy", remaining).0;
            }
        }
        observed
    }

    fn failed_identity(&self, obs: &Observation) -> Self {
        let mut failed = self.clone();
        // A member check is allowed to resolve by name only until a concrete failing
        // peer is known. Its record retains member provenance even when rechecked by IP.
        if failed.peer.is_none() {
            if let (Some(address), Ok((_, port, _))) =
                (obs.peer_address, build_request(&self.method, &self.host))
            {
                failed.peer = Some((address, port));
            }
        }
        if self.borrowed && obs.country.is_some() {
            if let Some((name, method)) = failed.alternative.take() {
                if obs.host == name && obs.method == method.id {
                    failed.host = name;
                    failed.method = method;
                }
            }
        }
        failed
    }
}

struct FailedTarget {
    target: Target,
    observation: Observation,
    generation: u64,
    dns_current: bool,
}

#[derive(Default)]
pub(super) struct Failures {
    targets: Vec<FailedTarget>,
    pub generation: u64,
    overflow: bool,
}

impl Failures {
    pub fn overflowed(&self) -> bool {
        self.overflow
    }

    pub fn reset_if_edited(&mut self, old: &EgressConfig, cfg: &EgressConfig, group: &Group) {
        if !self.overflow {
            return;
        }
        let Some(previous) = old.group(group.id) else {
            return;
        };
        let names_changed = previous.members.len() != group.members.len()
            || previous.members.iter().any(|m| !group.members.contains(m));
        let countries_changed = previous.expect.len() != group.expect.len()
            || previous
                .expect
                .iter()
                .any(|v| !group.expect.iter().any(|w| w.eq_ignore_ascii_case(v)));
        let ranges_changed = previous.cidrs.len() != group.cidrs.len()
            || previous.cidrs.iter().any(|v| !group.cidrs.contains(v));
        let methods_changed = group
            .members
            .iter()
            .filter_map(|m| m.method.as_deref())
            .any(|id| match (old.method(id), cfg.method(id)) {
                (Some(a), Some(b)) => a.url != b.url || a.head != b.head || a.extract != b.extract,
                (None, None) => false,
                _ => true,
            });
        if names_changed
            || countries_changed
            || ranges_changed
            || methods_changed
            || previous.exit_range_check != group.exit_range_check
            || previous.exit_ranges != group.exit_ranges
        {
            *self = Self::default();
        }
    }

    pub fn plan(&self, cfg: &EgressConfig, group: &Group, check: &CheckMsg) -> Vec<Target> {
        if group.simple() {
            // A protected app's connection is probed at its own destination,
            // with the name it showed (a cover name still reaches the same edge).
            let (Some(host), Some(method)) = (check.host.as_ref(), cfg.method(super::PRESET_TRACE)) else { return Vec::new() };
            if !super::valid_host(host) { return Vec::new(); }
            return vec![Target {
                host: host.to_ascii_lowercase(),
                method,
                peer: Some((check.ip, check.port.get())),
                borrowed: false,
                named_flow: check.host_confirmed,
                alternative: None,
            }];
        }
        let mut targets = Vec::new();
        let direct: Vec<_> = probe_targets(cfg, group, check.host.as_deref())
            .into_iter()
            .filter(|(_, method)| method.is_direct())
            .collect();
        let name_matches = |name: &str| {
            check.host.as_ref().is_some_and(|hint| {
                hint.trim_end_matches('.')
                    .eq_ignore_ascii_case(name.trim_end_matches('.'))
            })
        };
        let borrowed_index = if !check.host_confirmed || check.host.is_none() {
            direct
                .iter()
                .position(|(name, _)| name_matches(name))
                .or_else(|| check.host.is_none().then_some(0))
        } else {
            None
        };
        let alternative = borrowed_index.and_then(|index| {
            direct
                .iter()
                .enumerate()
                .find(|(i, _)| *i != index)
                .map(|(_, candidate)| candidate.clone())
        });
        for (index, (host, method)) in direct.into_iter().enumerate() {
            let borrowed = borrowed_index == Some(index);
            let named = check.host_confirmed && name_matches(&host);
            let target = Target {
                host,
                method,
                peer: (borrowed || named).then_some((check.ip, check.port.get())),
                borrowed,
                named_flow: named,
                alternative: if borrowed { alternative.clone() } else { None },
            };
            if !targets.contains(&target) {
                targets.push(target);
            }
        }
        if targets.iter().any(Target::direct_flow) {
            targets.retain(Target::direct_flow);
            return targets;
        }
        for failed in &self.targets {
            if !targets.contains(&failed.target) {
                targets.push(failed.target.clone());
            }
        }
        targets
    }

    /// A late failure is still a reason to block. Only current evidence can clear a failure.
    pub fn evaluate(
        &mut self,
        group: &Group,
        generation: u64,
        results: &[(Target, Observation)],
    ) -> bool {
        let current = generation == self.generation;
        let direct = !results.is_empty() && results.iter().all(|(t, _)| t.direct_flow());
        let passed = |o: &Observation| {
            o.failure_reason.is_none()
                && o.error.is_none()
                && o.country.as_ref().is_some_and(|country| {
                    group
                        .expect
                        .iter()
                        .any(|expected| expected.eq_ignore_ascii_case(country))
                })
        };
        if current || direct {
            self.targets.retain(|old| {
                old.generation > generation
                    || !results
                        .iter()
                        .any(|(target, obs)| target == &old.target && passed(obs))
            });
        }
        let mut failed = results.is_empty();
        let next = self.generation.saturating_add(1);
        for (target, obs) in results {
            if passed(obs) {
                continue;
            }
            failed = true;
            let target = target.failed_identity(obs);
            let entry = FailedTarget {
                target,
                observation: obs.clone(),
                generation: next,
                dns_current: true,
            };
            if let Some(old) = self.targets.iter_mut().find(|f| f.target == entry.target) {
                *old = entry;
            } else if self.targets.len() < MAX_FAILED_TARGETS {
                self.targets.push(entry);
            } else {
                self.overflow = true;
            }
        }
        if failed {
            self.generation = next;
        }
        if failed || self.overflow {
            return false;
        }
        if direct {
            return !self
                .targets
                .iter()
                .any(|old| results.iter().any(|(t, _)| t == &old.target));
        }
        current && self.targets.is_empty()
    }

    pub fn pending_targets(&self) -> Vec<Target> {
        self.targets.iter().map(|f| f.target.clone()).collect()
    }

    pub fn approval_for(&self, obs: &Observation) -> Option<String> {
        if let Some(id) = self
            .targets
            .iter()
            .map(|f| &f.observation)
            .find(|old| {
                old.approval_id.is_some()
                    && old.host.eq_ignore_ascii_case(&obs.host)
                    && old.method == obs.method
                    && old.evidence == obs.evidence
                    && old.peer_address == obs.peer_address
                    && old.ip == obs.ip
                    && old.country == obs.country
                    && old.failure_reason == obs.failure_reason
            })
            .and_then(|old| old.approval_id.clone())
        {
            return Some(id);
        }
        let mut bytes = [0u8; 16];
        (unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } == 0)
            .then(|| format!("{:032x}", u128::from_be_bytes(bytes)))
    }

    pub fn invalidate_dns(&mut self) {
        for entry in &mut self.targets {
            entry.dns_current = false;
            entry.observation.approval_id = None;
        }
    }

    pub fn wrong_ipv4(
        &self,
        group: &Group,
        name: &str,
        candidates: &[std::net::Ipv4Addr],
    ) -> Vec<std::net::Ipv4Addr> {
        self.targets
            .iter()
            .filter_map(|f| {
                let obs = &f.observation;
                let country = obs.country.as_deref()?;
                if !f.dns_current
                    || !f.target.direct_flow()
                    || obs.evidence.as_deref() != Some("direct")
                    || !obs.host.trim_end_matches('.').eq_ignore_ascii_case(name)
                    || obs.error.is_some()
                    || group.expect.is_empty()
                    || group.expect.iter().any(|v| v.eq_ignore_ascii_case(country))
                {
                    return None;
                }
                let IpAddr::V4(ip) = obs.peer_address? else {
                    return None;
                };
                (f.target.peer.map(|p| p.0) == Some(IpAddr::V4(ip)) && candidates.contains(&ip))
                    .then_some(ip)
            })
            .collect()
    }

    pub fn observed_failures(&self) -> Vec<Observation> {
        self.targets
            .iter()
            .map(|f| f.observation.clone())
            .chain(self.diagnostic())
            .collect()
    }

    pub fn diagnostic(&self) -> Option<Observation> {
        self.overflow.then(|| Observation {
            error: Some("组内未核实的地址超过上限，仍在拦截。可停用该组后重新启用。".into()),
            ..Default::default()
        })
    }

    pub fn update(&mut self, cfg: &EgressConfig, group: &Group) {
        let mut retained: Vec<FailedTarget> = Vec::new();
        for mut entry in self.targets.drain(..) {
            let target = &mut entry.target;
            let mut matching = group
                .members
                .iter()
                .filter(|m| pattern_matches(&m.pattern, &target.host));
            let member = matching
                .clone()
                .find(|m| m.method.as_deref() == Some(&target.method.id))
                .or_else(|| matching.find(|m| m.method.is_some()));
            let Some(method) = member.and_then(|m| cfg.method(m.method.as_deref()?)) else {
                continue;
            };
            if !method.is_direct() {
                continue;
            }
            if let Some((name, previous)) = target.alternative.take() {
                let updated = group
                    .members
                    .iter()
                    .find(|m| {
                        pattern_matches(&m.pattern, &name)
                            && m.method.as_deref() == Some(previous.id.as_str())
                    })
                    .and_then(|m| cfg.method(m.method.as_deref()?))
                    .filter(ProbeMethod::is_direct);
                target.alternative = updated.map(|m| (name, m));
            }
            target.method = method;
            if !retained.iter().any(|f| f.target == entry.target) {
                retained.push(entry);
            }
        }
        self.targets = retained;
    }
}

pub(super) fn unconfirmed(plan: &[Target], reason: &str) -> Vec<(Target, Observation)> {
    plan.iter()
        .map(|t| (t.clone(), t.unconfirmed(reason)))
        .collect()
}
