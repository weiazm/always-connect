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
        if names_changed || countries_changed || ranges_changed || methods_changed {
            *self = Self::default();
        }
    }

    pub fn plan(&self, cfg: &EgressConfig, group: &Group, check: &CheckMsg) -> Vec<Target> {
        let mut targets = Vec::new();
        let direct: Vec<_> = probe_targets(cfg, group, check.host.as_deref())
            .into_iter()
            .filter(|(_, method)| method.is_direct())
            .collect();
        let alternative = direct.get(1).cloned();
        for (index, (host, method)) in direct.into_iter().enumerate() {
            let borrowed = check.host.is_none() && index == 0;
            let named = check.host.as_ref().is_some_and(|name| {
                name.trim_end_matches('.')
                    .eq_ignore_ascii_case(host.trim_end_matches('.'))
            });
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
            o.country.as_ref().is_some_and(|country| {
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
