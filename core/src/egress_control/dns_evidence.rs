//! Serialize delivered DNS evidence on the same private stream as gate configuration.
use super::*;
use crate::dns_forwarder::{DeliveredDns, DeliveredDnsKind};
use crate::egress_gate::evidence_clock_ms;

const MAX_AGE_MS: u64 = 300_000;

#[derive(Default)]
pub(super) struct EvidenceScope {
    epoch: Option<u64>,
    generation: u64,
    changed_at: Option<u64>,
    suppressed_until: u64,
    announced: bool,
}

impl ControlState {
    // Config/invalidate frames already clear the gate. The first new record must announce its generation.
    pub(super) fn invalidate_delivered_dns(&mut self) {
        let scope = &mut self.dns_evidence;
        scope.generation = scope.generation.wrapping_add(1).max(1);
        scope.changed_at = evidence_clock_ms();
        scope.announced = false;
    }

    fn suspend_dns_compatibility(&mut self) {
        let now = evidence_clock_ms();
        let was_active = now.is_none_or(|now| self.dns_evidence.suppressed_until <= now);
        self.dns_evidence.suppressed_until =
            now.map_or(u64::MAX, |now| now.saturating_add(MAX_AGE_MS));
        if was_active {
            self.reset_dns_stream();
        }
    }

    fn reset_dns_stream(&mut self) {
        let had_records = self.dns_evidence.announced;
        self.invalidate_delivered_dns();
        if had_records {
            self.send(&serde_json::json!({"dnsReset":self.dns_evidence.generation}).to_string());
            self.dns_evidence.announced = self.peer.is_some();
        }
    }
}

impl Controller {
    pub(crate) fn set_dns_epoch(&self, epoch: Option<u64>) {
        let mut state = self.shared.state.lock().expect("controller");
        if state.dns_evidence.epoch != epoch {
            state.dns_evidence.epoch = epoch;
            state.reset_dns_stream();
        }
    }

    pub(crate) fn dns_delivery_loss(&self, epoch: u64) {
        let mut state = self.shared.state.lock().expect("controller");
        if state.dns_evidence.epoch != Some(epoch) {
            return;
        }
        state.suspend_dns_compatibility();
    }

    pub(crate) fn delivered_dns(
        &self,
        record: &DeliveredDns,
        interface: &str,
        routes: &ProtectedRoutes,
    ) {
        use crate::egress_gate::Classifier;
        let mut state = self.shared.state.lock().expect("controller");
        if !state.config.active()
            || !state.config.block_unidentified_web
            || state.peer.is_none()
            || state.status.interface != interface
            || interface.is_empty()
            || state.dns_evidence.epoch != Some(record.epoch)
        {
            return;
        }
        let Some(now) = evidence_clock_ms() else {
            state.suspend_dns_compatibility();
            return;
        };
        let scope = &state.dns_evidence;
        if !scope
            .changed_at
            .is_some_and(|boundary| record.observed_at_ms >= boundary)
            || record.started_at_ms > record.observed_at_ms
            || record.observed_at_ms > now
            || now.saturating_sub(record.observed_at_ms) >= MAX_AGE_MS
        {
            return;
        }
        let protected = routes.group_for_name(&record.name).is_some();
        let scoped_withdrawal = record.scope_known && record.values.is_empty() && !protected;
        if (record.incomplete && !scoped_withdrawal) || record.values.len() > 16 {
            state.suspend_dns_compatibility();
            return;
        }
        // During an evidence gap, keep subsequent protected associations.
        // Their TTL may extend past the end of the ordinary-traffic hold.
        if !scope
            .changed_at
            .is_some_and(|boundary| record.started_at_ms > boundary)
            || (!protected && record.started_at_ms < scope.suppressed_until)
        {
            return;
        }
        let kind = match record.kind {
            DeliveredDnsKind::Ipv4 if record.qtype == 1 => "ipv4",
            DeliveredDnsKind::Ipv6 if record.qtype == 28 => "ipv6",
            DeliveredDnsKind::Ech if matches!(record.qtype, 64 | 65) => "ech",
            _ => return,
        };
        let generation = scope.generation;
        if !scope.announced {
            state.send(&serde_json::json!({"dnsReset":generation}).to_string());
            if state.peer.is_none() {
                return;
            }
            state.dns_evidence.announced = true;
        }
        let values: Vec<_> = record
            .values
            .iter()
            .map(|v| serde_json::json!({"value":v.value,"ttl":v.ttl.min(300)}))
            .collect();
        let message = serde_json::json!({"dnsEvidence":{"generation":generation,"name":record.name,
            "kind":kind,"qtype":record.qtype,"observedAtMs":record.observed_at_ms,"values":values}});
        state.send(&message.to_string());
    }
}
