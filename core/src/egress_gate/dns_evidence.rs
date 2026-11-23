//! Current DNS associations for the unidentified traffic fallback.
//! The name index owns RRset replacement. The address index limits the work
//! required to consider a connection's candidates.

use super::{is_site_name, norm, Classifier, GroupId};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

const MAX_TTL_MS: u64 = 300_000;
const MAX_NAMES: usize = 512;
const MAX_ADDRESSES: usize = 4096;
const MAX_PER_RRSET: usize = 16;
const MAX_NAMES_PER_ADDRESS: usize = 16;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsEvidenceUpdate {
    pub generation: u64,
    pub name: String,
    pub kind: DnsEvidenceKind,
    pub observed_at_ms: u64,
    pub qtype: u16,
    pub values: Vec<DnsEvidenceValue>,
}

#[derive(Clone, Copy, Debug, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsEvidenceKind {
    Ipv4,
    Ipv6,
    Ech,
}

#[derive(Debug, serde::Deserialize)]
pub struct DnsEvidenceValue {
    pub value: String,
    pub ttl: u32,
}

struct Until<T> {
    value: T,
    at_ms: u64,
}

struct Rrset<T> {
    observed_at_ms: u64,
    values: Vec<Until<T>>,
}

impl<T> Default for Rrset<T> {
    fn default() -> Self {
        Self { observed_at_ms: 0, values: Vec::new() }
    }
}

impl<T> Rrset<T> {
    fn retain_live(&mut self, now: u64) -> bool {
        self.values.retain(|entry| entry.at_ms > now);
        self.observed_at_ms != 0 && self.observed_at_ms.saturating_add(MAX_TTL_MS) > now
    }
}

#[derive(Default)]
struct NameEvidence {
    ipv4: Rrset<IpAddr>,
    ipv6: Rrset<IpAddr>,
    ech: [Rrset<String>; 2],
}

#[derive(Default)]
struct AddressEvidence {
    names: Vec<Until<Arc<str>>>,
    overflow_until: u64,
}

pub(super) enum DnsMatch {
    Ordinary,
    Protected(GroupId, Option<Arc<str>>),
    ConflictingProtection,
    Unknown,
}

impl DnsMatch {
    pub(super) fn conflicts_with(&self, group: Option<GroupId>) -> bool {
        match self {
            Self::ConflictingProtection => true,
            Self::Protected(associated, _) => group.is_some_and(|known| known != *associated),
            Self::Ordinary | Self::Unknown => false,
        }
    }
}

#[derive(Default)]
pub(super) struct DnsEvidence {
    generation: Option<u64>,
    last_generation: Option<u64>,
    names: HashMap<Arc<str>, NameEvidence>,
    addresses: HashMap<IpAddr, AddressEvidence>,
    incomplete_until: u64,
    prune_after: u64,
    sweep_after: u64,
}

impl DnsEvidence {
    pub(super) fn clear(&mut self) {
        *self = Self { last_generation: self.last_generation, ..Self::default() };
    }

    pub(super) fn enable(&mut self, generation: u64) {
        if self.last_generation.is_some_and(|last| generation <= last) {
            return;
        }
        self.clear();
        self.generation = Some(generation);
        self.last_generation = Some(generation);
    }

    pub(super) fn active(&self) -> bool {
        self.generation.is_some()
    }

    pub(super) fn sweep(&mut self, clock: fn() -> Option<u64>) {
        if self.names.is_empty() && self.addresses.is_empty() {
            return;
        }
        let Some(now) = clock() else { return };
        if now < self.sweep_after {
            return;
        }
        self.sweep_after = now.saturating_add(30_000);
        self.prune(now);
        if self.names.is_empty() && self.addresses.is_empty() {
            self.names.shrink_to_fit();
            self.addresses.shrink_to_fit();
        }
    }

    pub(super) fn update(&mut self, update: DnsEvidenceUpdate, now: u64) {
        if self.generation != Some(update.generation) || update.observed_at_ms == 0 || update.observed_at_ms > now
            || update.observed_at_ms.saturating_add(MAX_TTL_MS) <= now
            || !matches!((update.kind, update.qtype),
                (DnsEvidenceKind::Ipv4, 1) | (DnsEvidenceKind::Ipv6, 28) | (DnsEvidenceKind::Ech, 64 | 65))
        {
            return;
        }
        let Some(name) = site_name(&update.name) else { return };
        let observed = update.observed_at_ms;
        if update.values.len() > MAX_PER_RRSET {
            self.mark_incomplete(observed.saturating_add(MAX_TTL_MS));
            return;
        }
        if self.names.len() >= MAX_NAMES || self.addresses.len() >= MAX_ADDRESSES - MAX_PER_RRSET {
            self.prune(now);
        }
        let name: Arc<str> = name.into();
        if !self.names.contains_key(name.as_ref()) && self.names.len() >= MAX_NAMES {
            self.mark_incomplete(observed.saturating_add(MAX_TTL_MS));
            return;
        }
        let until = |ttl: u32| observed.saturating_add((u64::from(ttl) * 1000).min(MAX_TTL_MS));
        let values = update.values.into_iter().filter(|entry| until(entry.ttl) > now);
        match update.kind {
            DnsEvidenceKind::Ech => {
                let slot = usize::from(update.qtype == 65);
                let current = &mut self.names.entry(name).or_default().ech[slot];
                if current.observed_at_ms > observed {
                    return;
                }
                let Some(values) = values
                    .map(|entry| Some(Until { value: site_name(&entry.value)?, at_ms: until(entry.ttl) }))
                    .collect::<Option<Vec<_>>>()
                else {
                    self.mark_incomplete(observed.saturating_add(MAX_TTL_MS));
                    return;
                };
                *current = Rrset { observed_at_ms: observed, values };
            }
            kind => {
                let ipv4 = matches!(kind, DnsEvidenceKind::Ipv4);
                if let Some(current) = self.names.get(name.as_ref()).map(|entry| if ipv4 { &entry.ipv4 } else { &entry.ipv6 }) {
                    if current.observed_at_ms > observed {
                        return;
                    }
                }
                let Some(values) = values.map(|entry| {
                    let address: IpAddr = entry.value.parse().ok()?;
                    (address.is_ipv4() == ipv4).then(|| Until { value: address, at_ms: until(entry.ttl) })
                }).collect::<Option<Vec<_>>>()
                else {
                    self.mark_incomplete(observed.saturating_add(MAX_TTL_MS));
                    return;
                };
                self.replace_addresses(name, ipv4, Rrset { observed_at_ms: observed, values }, now);
            }
        }
    }

    fn replace_addresses(&mut self, name: Arc<str>, ipv4: bool, replacement: Rrset<IpAddr>, now: u64) {
        let entry = self.names.entry(name.clone()).or_default();
        let current = if ipv4 { &mut entry.ipv4 } else { &mut entry.ipv6 };
        let old = std::mem::replace(current, replacement);
        for address in old.values {
            if let Some(entry) = self.addresses.get_mut(&address.value) {
                entry.names.retain(|other| other.value.as_ref() != name.as_ref());
                if entry.names.is_empty() && entry.overflow_until <= now {
                    self.addresses.remove(&address.value);
                }
            }
        }
        for address in &current.values {
            if self.addresses.len() >= MAX_ADDRESSES && !self.addresses.contains_key(&address.value) {
                self.incomplete_until = self.incomplete_until.max(address.at_ms);
                continue;
            }
            let entry = self.addresses.entry(address.value).or_default();
            entry.names.retain(|other| other.at_ms > now);
            if let Some(link) = entry.names.iter_mut().find(|other| other.value == name) {
                link.at_ms = link.at_ms.min(address.at_ms);
            } else if entry.names.len() < MAX_NAMES_PER_ADDRESS {
                entry.names.push(Until { value: name.clone(), at_ms: address.at_ms });
            } else {
                entry.overflow_until = entry.overflow_until.max(address.at_ms);
            }
        }
    }

    fn mark_incomplete(&mut self, until: u64) {
        self.incomplete_until = self.incomplete_until.max(until);
    }

    fn prune(&mut self, now: u64) {
        if now < self.prune_after {
            return;
        }
        self.prune_after = now.saturating_add(1000);
        self.names.retain(|_, entry| {
            let ipv4 = entry.ipv4.retain_live(now);
            let ipv6 = entry.ipv6.retain_live(now);
            let ech = entry.ech.each_mut().map(|set| set.retain_live(now));
            ipv4 || ipv6 || ech.into_iter().any(|live| live)
        });
        self.prune_addresses(now);
    }

    fn prune_addresses(&mut self, now: u64) {
        self.addresses.retain(|_, entry| {
            entry.names.retain(|link| link.at_ms > now);
            !entry.names.is_empty() || entry.overflow_until > now
        });
    }

    pub(super) fn classify(&self, address: IpAddr, outer: Option<&str>, now: u64, classifier: &dyn Classifier) -> DnsMatch {
        let Some(entry) = self.addresses.get(&address) else { return DnsMatch::Unknown };
        let mut group = None;
        let mut matching_name = None;
        let mut matches_outer = false;
        for link in entry.names.iter().filter(|link| link.at_ms > now) {
            if let Some(protected) = classifier.group_for_name(&link.value) {
                if let Some(earlier) = group {
                    if earlier != protected {
                        return DnsMatch::ConflictingProtection;
                    }
                    matching_name = None;
                } else {
                    group = Some(protected);
                    matching_name = Some(link.value.clone());
                }
            } else if outer.is_some_and(|outer| {
                link.value.as_ref() == outer || self.names.get(link.value.as_ref()).is_some_and(|name|
                    name.ech.iter().any(|set| set.values.iter().any(|link| link.at_ms > now && link.value == outer)))
            }) {
                matches_outer = true;
            }
        }
        if entry.overflow_until > now {
            return DnsMatch::ConflictingProtection;
        }
        if let Some(group) = group {
            return DnsMatch::Protected(group, matching_name);
        }
        if matches_outer && self.incomplete_until <= now {
            DnsMatch::Ordinary
        } else {
            DnsMatch::Unknown
        }
    }
}

fn site_name(name: &str) -> Option<String> {
    if name.len() > 254 {
        return None;
    }
    let name = norm(name);
    is_site_name(&name).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rules;

    impl Classifier for Rules {
        fn group_for_name(&self, name: &str) -> Option<GroupId> {
            (name == "protected.example").then_some(1)
        }

        fn group_for_ip(&self, _: IpAddr) -> Option<GroupId> {
            None
        }
    }

    fn record(cache: &mut DnsEvidence, name: &str, ttl: u32) {
        cache.update(DnsEvidenceUpdate {
            generation: 9, name: name.into(), kind: DnsEvidenceKind::Ipv4, qtype: 1,
            observed_at_ms: 5_000,
            values: vec![DnsEvidenceValue { value: "192.0.2.10".into(), ttl }],
        }, 10_000);
    }

    #[test]
    fn ttl_is_capped_from_observation_and_family_mismatch_cannot_replace_the_record() {
        let mut cache = DnsEvidence::default();
        cache.enable(9);
        record(&mut cache, "ordinary.example", 3600);
        cache.update(DnsEvidenceUpdate {
            generation: 9, name: "ordinary.example".into(), kind: DnsEvidenceKind::Ipv4, qtype: 28,
            observed_at_ms: 10_000, values: vec![],
        }, 10_000);
        let ip = "192.0.2.10".parse().unwrap();
        assert!(matches!(cache.classify(ip, Some("ordinary.example"), 304_999, &Rules), DnsMatch::Ordinary));
        assert!(matches!(cache.classify(ip, Some("ordinary.example"), 305_000, &Rules), DnsMatch::Unknown));
    }

    #[test]
    fn an_overflowed_address_cannot_be_classified_as_ordinary() {
        let mut cache = DnsEvidence::default();
        cache.enable(9);
        for index in 0..MAX_NAMES_PER_ADDRESS {
            record(&mut cache, &format!("ordinary-{index}.example"), 60);
        }
        record(&mut cache, "protected.example", 60);
        let ip = "192.0.2.10".parse().unwrap();
        assert_eq!(cache.addresses[&ip].names.len(), MAX_NAMES_PER_ADDRESS);
        assert!(matches!(cache.classify(ip, Some("ordinary-0.example"), 10_000, &Rules), DnsMatch::ConflictingProtection));
    }
}
