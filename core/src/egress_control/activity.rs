//! Session counts use actual flow denials reported by the gate, independently of probes.
use super::*;

const MAX_SITE_COUNTS: usize = 32;

#[derive(Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct Denied {
    group: u32,
    count: u64,
    #[serde(default)]
    hosts: Vec<HostCount>,
    last_host: Option<String>,
}

#[derive(Clone, Deserialize)]
struct HostCount {
    host: String,
    count: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteStatus {
    host: String,
    state: String,
    last_check: f64,
    country: Option<String>,
    blocked_count: u64,
}

impl GroupStatus {
    fn site(&mut self, name: &str) -> Option<&mut SiteStatus> {
        let index = self.sites.iter().position(|s| s.host == name);
        match index {
            Some(i) => self.sites.get_mut(i),
            None if self.sites.len() < MAX_SITE_COUNTS => {
                self.sites.push(SiteStatus {
                    host: name.into(),
                    state: "unknown".into(),
                    ..Default::default()
                });
                self.sites.last_mut()
            }
            _ => None,
        }
    }

    pub(super) fn observe_sites(&mut self, group: &Group, observations: &[Observation], at: f64) {
        for obs in observations {
            if !valid_host(&obs.host) {
                continue;
            }
            if let Some(site) = self.site(&obs.host) {
                site.last_check = at;
                site.country = obs.country.clone();
                site.state = if decide(group, std::slice::from_ref(obs)) {
                    "ok"
                } else if obs.evidence.as_deref() == Some("direct") && obs.country.is_some() {
                    "partial"
                } else {
                    "blocked"
                }
                .into();
            }
        }
    }

    pub(super) fn level(&self) -> &'static str {
        if self.reason.is_some() {
            return "blocked";
        }
        match self.state.as_str() {
            "ok" => "ok",
            "blocked"
                if !self.observed.is_empty()
                    && self.observed.iter().all(|o| {
                        o.evidence.as_deref() == Some("direct") && o.country.is_some()
                    }) =>
            {
                "partial"
            }
            "blocked" => "blocked",
            _ => "unknown",
        }
    }
}

impl ControlState {
    pub(super) fn denied_counts(&mut self, reports: Vec<Denied>) {
        for report in reports.into_iter().take(MAX_GROUPS) {
            let Some(group) = self
                .config
                .group(report.group)
                .filter(|g| self.config.active() && g.enabled)
            else {
                continue;
            };
            if report.hosts.len() > MAX_SITE_COUNTS {
                continue;
            }
            let previous = self.peer_counts.entry(group.id).or_default();
            if report.count < previous.count {
                continue;
            }
            let delta = report.count - previous.count;
            let st = match self.status.groups.iter_mut().find(|g| g.id == group.id) {
                Some(st) => st,
                None => {
                    self.status.groups.push(GroupStatus {
                        id: group.id,
                        name: group.name.clone(),
                        state: "unknown".into(),
                        ..Default::default()
                    });
                    self.status.groups.last_mut().unwrap()
                }
            };
            st.blocked_count = st.blocked_count.saturating_add(delta);
            if delta > 0 {
                st.last_blocked_host = report.last_host.clone().filter(|v| valid_host(v));
                st.last_blocked_country = st.last_blocked_host.as_ref().and_then(|h| {
                    st.observed
                        .iter()
                        .find(|o| o.evidence.as_deref() == Some("direct") && o.host == *h)
                        .and_then(|o| o.country.clone())
                });
            }
            for row in &report.hosts {
                if !valid_host(&row.host) {
                    continue;
                }
                let old = previous
                    .hosts
                    .iter()
                    .find(|o| o.host == row.host)
                    .map_or(0, |o| o.count);
                if let Some(site) = st.site(&row.host) {
                    site.blocked_count = site
                        .blocked_count
                        .saturating_add(row.count.saturating_sub(old).min(delta));
                }
            }
            *previous = report;
        }
    }
}
