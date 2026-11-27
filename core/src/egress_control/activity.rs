//! Session counts use actual flow denials reported by the gate, independently of probes.
use super::*;

const MAX_SITE_COUNTS: usize = 32;
const MAX_PATH_STATUSES: usize = 16;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}

/// Per-path summary for one protection rule (DESIGN.md §71).
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathStatus {
    pub path: String,
    pub state: String,
    pub last_check: f64,
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub blocked_count: u64,
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

    fn path_entry(&mut self, wire: &str) -> Option<&mut PathStatus> {
        if let Some(i) = self.paths.iter().position(|p| p.path == wire) {
            return self.paths.get_mut(i);
        }
        if self.paths.len() >= MAX_PATH_STATUSES {
            if let Some(oldest) = self.paths.iter().enumerate()
                .min_by(|a, b| a.1.last_check.total_cmp(&b.1.last_check))
                .map(|(i, _)| i)
            {
                self.paths.remove(oldest);
            }
        }
        self.paths.push(PathStatus {
            path: wire.into(),
            state: "unknown".into(),
            ..Default::default()
        });
        self.paths.last_mut()
    }

    pub(super) fn observe_site(&mut self, group: &Group, obs: &Observation, at: f64) {
        let obs_state = match obs.country.as_deref() {
            Some(country) if group.allows(country) => "ok",
            Some(_) => "blocked",
            None if group.unverified == Unverified::Block => "blocked",
            None => "unknown",
        };
        if let Some(wire) = obs.path.as_deref() {
            self.path = Some(wire.to_owned());
            if let Some(entry) = self.path_entry(wire) {
                entry.last_check = at;
                entry.state = obs_state.into();
                entry.country = obs.country.clone();
                entry.ip = obs.ip.clone();
                entry.error = obs.error.clone();
            }
        }
        if !valid_host(&obs.host) {
            return;
        }
        if let Some(site) = self.site(&obs.host) {
            site.last_check = at;
            site.country = obs.country.clone();
            site.path = obs.path.clone();
            site.state = obs_state.into();
        }
    }
}

impl ControlState {
    pub(super) fn note_unverified(&mut self, group: &Group) {
        let status = self.status.group(group);
        status.unverified_count = status.unverified_count.saturating_add(1);
    }

    /// Increment denial counts immediately for a connection blocked by the
    /// in-process proxy/local relay (§71).
    pub(super) fn note_relay_denied(&mut self, group: &Group, host: &str, path: &EgressPath) {
        let wire = path.wire();
        let st = self.status.group(group);
        st.blocked_count = st.blocked_count.saturating_add(1);
        if valid_host(host) {
            st.last_blocked_host = Some(host.to_owned());
            st.last_blocked_country = st.observed.iter()
                .find(|o| o.host == host && o.path.as_deref() == Some(wire.as_str()))
                .or_else(|| st.observed.iter().find(|o| o.host == host))
                .and_then(|o| o.country.clone());
            if let Some(site) = st.site(host) {
                site.blocked_count = site.blocked_count.saturating_add(1);
                site.path = Some(wire.clone());
            }
        }
        if let Some(entry) = st.path_entry(&wire) {
            entry.blocked_count = entry.blocked_count.saturating_add(1);
        }
    }

    pub(super) fn denied_counts(&mut self, reports: Vec<Denied>) {
        for report in reports.into_iter().take(MAX_GROUPS) {
            let Some(group) = self.config.enabled_group(report.group).cloned() else {
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
            let st = self.status.group(&group);
            st.blocked_count = st.blocked_count.saturating_add(delta);
            if delta > 0 {
                st.last_blocked_host = report.last_host.clone().filter(|v| valid_host(v));
                st.last_blocked_country = st.last_blocked_host.as_ref().and_then(|h| {
                    st.observed
                        .iter()
                        .find(|o| o.host == *h)
                        .and_then(|o| o.country.clone())
                });
                if let Some(entry) = st.path_entry("cisco") {
                    entry.blocked_count = entry.blocked_count.saturating_add(delta);
                }
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
