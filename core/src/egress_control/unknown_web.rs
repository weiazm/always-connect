use super::*;
use crate::egress_gate::UnknownWebReason;
use std::net::SocketAddr;

const LIMIT: usize = 32;

#[derive(Deserialize)]
pub(super) struct UnknownCount {
    address: IpAddr,
    port: u16,
    count: u64,
    #[serde(default, rename = "lastReason")]
    last_reason: UnknownWebReason,
}

#[derive(Clone, Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UnknownWeb {
    address: IpAddr,
    port: u16,
    count: u64,
    allowed: bool,
    #[serde(skip_serializing_if = "UnknownWebReason::unspecified")]
    last_reason: UnknownWebReason,
    approval_id: String,
}

impl ControlState {
    pub(super) fn note_unknown(&mut self, rows: Vec<UnknownCount>) {
        if !self.config.active() || !self.config.block_unidentified_web || rows.len() > LIMIT {
            return;
        }
        for row in rows {
            if row.count == 0 || !matches!(row.port, 80 | 443 | 8443) {
                continue;
            }
            let key = SocketAddr::new(row.address, row.port);
            if !self.unknown_counts.contains_key(&key) && self.unknown_counts.len() >= LIMIT {
                continue;
            }
            let prior = self.unknown_counts.entry(key).or_default();
            if row.count <= *prior {
                continue;
            }
            let delta = row.count - *prior;
            *prior = row.count;
            self.status.unknown_web_count = self.status.unknown_web_count.saturating_add(delta);
            let records = &mut self.status.unknown_web;
            if let Some(known) = records
                .iter_mut()
                .find(|v| v.address == row.address && v.port == row.port)
            {
                known.count = known.count.saturating_add(delta);
                known.last_reason = row.last_reason;
                continue;
            }
            if records.len() >= LIMIT {
                let Some(index) = records.iter().position(|v| !v.allowed) else {
                    continue;
                };
                records.remove(index);
            }
            let mut bytes = [0u8; 16];
            if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
                continue;
            }
            records.push(UnknownWeb {
                address: row.address,
                port: row.port,
                count: delta,
                allowed: false,
                last_reason: row.last_reason,
                approval_id: format!("{:032x}", u128::from_be_bytes(bytes)),
            });
        }
    }

    pub(super) fn gate_config(&self, marker: &str) -> String {
        let exceptions: Vec<_> = self
            .status
            .unknown_web
            .iter()
            .filter(|v| v.allowed)
            .map(|v| serde_json::json!({"address":v.address,"port":v.port}))
            .collect();
        serde_json::json!({"probe_alpn":marker,"groups":self.config.gate_groups(),
            "blockUnidentifiedWeb":self.config.active() && self.config.block_unidentified_web,
            "unknownWebExceptions":exceptions,"unknownWebInternalCidrs":self.internal_cidrs})
        .to_string()
    }
}

impl Controller {
    pub fn session_internal_routes(&self, includes: &str) {
        let mut routes = Vec::new();
        for entry in includes.split(',').take(128) {
            let Some((ip, length)) = parse_cidr(entry) else {
                continue;
            };
            if length < if ip.is_ipv4() { 24 } else { 64 } {
                continue;
            }
            let Ok(network) = entry.parse::<crate::egress_source::SourcePrefix>() else {
                continue;
            };
            let canonical = network.to_string();
            if !routes.contains(&canonical) {
                routes.push(canonical);
            }
        }
        let mut state = self.shared.state.lock().expect("controller");
        if state.internal_cidrs == routes {
            return;
        }
        state.internal_cidrs = routes;
        let frame = state.gate_config(&self.shared.marker);
        state.epoch = state.epoch.wrapping_add(1);
        state.warm.invalidate();
        state.send(&frame);
        state.send("{\"invalidate\":true}");
    }

    pub fn unknown_exception(
        &self,
        address: IpAddr,
        port: u16,
        allow: bool,
        approval_id: &str,
    ) -> bool {
        let mut state = self.shared.state.lock().expect("controller");
        if state.peer.is_none()
            || state.status.interface.is_empty()
            || !state.config.active()
            || !state.config.block_unidentified_web
            || approval_id.is_empty()
        {
            return false;
        }
        if allow
            && crate::egress_gate::Classifier::group_for_ip(
                &state.config.protected_routes(),
                address,
            )
            .is_some()
        {
            return false;
        }
        let Some(row) = state
            .status
            .unknown_web
            .iter_mut()
            .find(|r| r.address == address && r.port == port && r.approval_id == approval_id)
        else {
            return false;
        };
        if row.allowed != allow {
            row.allowed = allow;
            let config = state.gate_config(&self.shared.marker);
            state.warm.invalidate();
            state.epoch = state.epoch.wrapping_add(1);
            state.send(&config);
            state.send("{\"invalidate\":true}");
            if state.peer.is_none() {
                if let Some(r) = state
                    .status
                    .unknown_web
                    .iter_mut()
                    .find(|r| r.address == address && r.port == port)
                {
                    r.allowed = false;
                }
                return false;
            }
        }
        true
    }
}
