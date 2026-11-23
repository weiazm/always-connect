//! Compatibility evidence from the final downstream wire reply. This decoder
//! is deliberately independent of how an upstream answer is used for routing.

use super::{TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_DNAME, TYPE_HTTPS, TYPE_NS, TYPE_SOA, TYPE_SVCB};
use std::net::{Ipv4Addr, Ipv6Addr};

const MAX_PACKET: usize = 8192;
const MAX_RECORDS: usize = 64;
const MAX_ALIASES: usize = 8;
const MAX_VALUES: usize = 32;
const MAX_TTL: u32 = 300;
const IN: u16 = 1;
const OPT: u16 = 41;
const ECH: u16 = 5;
const ECH_CONFIG_VERSION: u16 = 0xfe0d;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveredDnsKind {
    Ipv4,
    Ipv6,
    Ech,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DeliveredDnsValue {
    pub value: String,
    /// Effective TTL in seconds, including all links in the answer.
    pub ttl: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DeliveredDns {
    pub epoch: u64,
    /// Shared boot-relative monotonic clock, in milliseconds.
    pub started_at_ms: u64,
    pub observed_at_ms: u64,
    /// Canonical name from the client's question.
    pub name: String,
    pub kind: DeliveredDnsKind,
    /// HTTPS and SVCB are independent RRsets even when both report ECH.
    pub qtype: u16,
    /// A matching delivered RRset could not be represented completely.
    pub incomplete: bool,
    /// For an incomplete event, the error is known to affect only this question.
    pub scope_known: bool,
    /// With incomplete=false, empty means the reply superseded this RRset.
    pub values: Vec<DeliveredDnsValue>,
}

struct Wire<'a> {
    bytes: &'a [u8],
    // Only already parsed label boundaries are valid pointer targets. Bytes
    // from an opaque RR must never be interpreted as a trusted owner name.
    labels: [u64; MAX_PACKET / 64],
}

impl<'a> Wire<'a> {
    fn new(bytes: &'a [u8]) -> Option<Self> {
        (12..=u16::MAX as usize)
            .contains(&bytes.len())
            .then(|| Self {
                bytes,
                labels: [0; MAX_PACKET / 64],
            })
    }

    fn name(&mut self, start: usize, stop: usize, compressed: bool) -> Option<(String, usize)> {
        let mut name = String::with_capacity(32);
        let mut at = start;
        let mut end = None;
        let mut hops = 0;
        let mut expanded = 1;
        loop {
            let len = usize::from(*self.bytes.get(at)?);
            if end.is_none() {
                if at >= stop || at >= MAX_PACKET {
                    return None;
                }
                self.labels[at / 64] |= 1 << (at % 64);
            }
            if len == 0 {
                return Some((name, end.unwrap_or(at + 1)));
            }
            if len & 0xc0 == 0xc0 {
                if !compressed || hops == 16 || (end.is_none() && at + 2 > stop) {
                    return None;
                }
                let target = (len & 0x3f) << 8 | usize::from(*self.bytes.get(at + 1)?);
                if target >= start || self.labels[target / 64] & (1 << (target % 64)) == 0 {
                    return None;
                }
                end.get_or_insert(at + 2);
                at = target;
                hops += 1;
                continue;
            }
            expanded += len + 1;
            if len > 63 || expanded > 255 || (end.is_none() && at + 1 + len >= stop) {
                return None;
            }
            let label = self.bytes.get(at + 1..at + 1 + len)?;
            if !label
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
            {
                return None;
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.extend(label.iter().map(|c| char::from(c.to_ascii_lowercase())));
            at += 1 + len;
        }
    }

    fn question(&mut self, qtype: u16) -> Option<(String, usize)> {
        if self.bytes[4..6] != [0, 1] {
            return None;
        }
        let (name, end) = self.name(12, self.bytes.len(), false)?;
        let fields = self.bytes.get(end..end + 4)?;
        (!name.is_empty() && u16_at(fields, 0)? == qtype && u16_at(fields, 2)? == IN)
            .then_some((name, end + 4))
    }

    fn record(&mut self, at: usize) -> Option<Record<'a>> {
        let (owner, end) = self.name(at, self.bytes.len(), true)?;
        let header = self.bytes.get(end..end + 10)?;
        let data = end + 10;
        let stop = data + usize::from(u16_at(header, 8)?);
        Some(Record {
            owner,
            kind: u16_at(header, 0)?,
            class: u16_at(header, 2)?,
            ttl: u32::from_be_bytes(header[4..8].try_into().ok()?),
            body: self.bytes.get(data..stop)?,
            data,
            stop,
        })
    }
}

struct Record<'a> {
    owner: String,
    kind: u16,
    class: u16,
    ttl: u32,
    body: &'a [u8],
    data: usize,
    stop: usize,
}

impl Record<'_> {
    fn valid_opt(&self) -> bool {
        self.owner.is_empty() && self.ttl >> 16 == 0 && valid_fields(self.body, false)
    }
}

enum Data<'a> {
    Alias(String),
    Address(&'a [u8]),
    Service {
        target: String,
        priority: u16,
        params: &'a [u8],
    },
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Option<&'a [u8]> {
    let value = bytes.get(..count)?;
    *bytes = &bytes[count..];
    Some(value)
}

fn vector<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = u16_at(take(bytes, 2)?, 0)?;
    take(bytes, usize::from(length))
}

fn field<'a>(bytes: &mut &'a [u8]) -> Option<(u16, &'a [u8])> {
    let key = u16_at(take(bytes, 2)?, 0)?;
    Some((key, vector(bytes)?))
}

fn valid_fields(mut bytes: &[u8], unique: bool) -> bool {
    let mut seen = Vec::new();
    while !bytes.is_empty() {
        let Some((key, _)) = field(&mut bytes) else {
            return false;
        };
        if unique {
            if seen.len() == MAX_RECORDS || seen.contains(&key) {
                return false;
            }
            seen.push(key);
        }
    }
    true
}

fn hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.parse::<Ipv4Addr>().is_err()
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}

// RFC 2181 treats TTLs with the high bit set as zero.
fn effective_ttl(ttl: u32) -> u32 {
    if ttl > i32::MAX as u32 {
        0
    } else {
        ttl.min(MAX_TTL)
    }
}

fn address_value(qtype: u16, bytes: &[u8]) -> Option<String> {
    match qtype {
        TYPE_A => Some(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?).to_string()),
        TYPE_AAAA => Some(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?).to_string()),
        _ => None,
    }
}

fn add_value(values: &mut Vec<DeliveredDnsValue>, value: String, ttl: u32) -> Option<()> {
    if let Some(old) = values.iter_mut().find(|old| old.value == value) {
        old.ttl = old.ttl.min(ttl);
    } else {
        if values.len() == MAX_VALUES {
            return None;
        }
        values.push(DeliveredDnsValue { value, ttl });
    }
    Some(())
}

fn ech_names(mut param: &[u8], ttl: u32, values: &mut Vec<DeliveredDnsValue>) -> Option<()> {
    let mut configs = vector(&mut param)?;
    if configs.is_empty() || !param.is_empty() {
        return None;
    }
    for _ in 0..MAX_VALUES {
        let (version, mut body) = field(&mut configs)?;
        if version != ECH_CONFIG_VERSION {
            return None;
        }
        take(&mut body, 3)?; // config_id and kem_id
        let key = vector(&mut body)?;
        let suites = vector(&mut body)?;
        let name_header = take(&mut body, 2)?; // maximum_name_length and public_name length
        let name = std::str::from_utf8(take(&mut body, usize::from(name_header[1]))?).ok()?;
        let extensions = vector(&mut body)?;
        if key.is_empty()
            || suites.is_empty()
            || suites.len() % 4 != 0
            || !body.is_empty()
            || !hostname(name)
            || !valid_fields(extensions, true)
        {
            return None;
        }
        add_value(values, name.to_ascii_lowercase(), ttl)?;
        if configs.is_empty() {
            return Some(());
        }
    }
    None
}

fn service_ech(params: &[u8]) -> Option<Option<&[u8]>> {
    let mut rest = params;
    let mut last = None;
    let mut mandatory = None;
    let mut ech = None;
    while !rest.is_empty() {
        let (key, value) = field(&mut rest)?;
        if last.is_some_and(|last| key <= last) || key == u16::MAX {
            return None;
        }
        match key {
            0 => mandatory = Some(value),
            ECH => ech = Some(value),
            _ => (),
        }
        last = Some(key);
    }
    if let Some(mut keys) = mandatory {
        if keys.is_empty() {
            return None;
        }
        let mut previous = 0;
        let mut available = params;
        while !keys.is_empty() {
            let key = u16_at(take(&mut keys, 2)?, 0)?;
            if key <= previous {
                return None;
            }
            previous = key;
            loop {
                let (candidate, _) = field(&mut available)?;
                if candidate > key {
                    return None;
                }
                if candidate == key {
                    break;
                }
            }
        }
    }
    Some(ech)
}

fn rrset_values(
    answers: &[(Record<'_>, Data<'_>)],
    name: &str,
    qtype: u16,
    rcode: u16,
    soa_owner: Option<&str>,
) -> Option<Vec<DeliveredDnsValue>> {
    let mut owner = name;
    let mut ttl = MAX_TTL;
    for depth in 0..=MAX_ALIASES {
        let mut alias = None;
        let mut records = Vec::new();
        for (record, data) in answers.iter().filter(|(record, _)| record.owner == owner) {
            ttl = ttl.min(effective_ttl(record.ttl));
            match data {
                Data::Alias(target) => {
                    if alias
                        .replace(target)
                        .is_some_and(|previous| previous != target)
                    {
                        return None;
                    }
                }
                // AliasMode requires a new lookup for another service name.
                Data::Service { priority: 0, .. } => return None,
                _ => records.push(data),
            }
        }
        if let Some(target) = alias {
            if !records.is_empty() || depth == MAX_ALIASES {
                return None;
            }
            owner = target;
            continue;
        }
        let has_negative_soa = soa_owner.is_some_and(|zone| {
            zone.is_empty()
                || owner == zone
                || owner
                    .strip_suffix(zone)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        });
        if (rcode == 3 && !records.is_empty())
            || (rcode == 0 && records.is_empty() && !answers.is_empty() && !has_negative_soa)
        {
            return None;
        }
        let mut values = Vec::new();
        for data in records {
            match data {
                Data::Address(bytes) => {
                    add_value(&mut values, address_value(qtype, bytes)?, ttl)?;
                }
                Data::Service { target, params, .. } => {
                    let ech = service_ech(params)?;
                    // The compatibility consumer correlates by question name.
                    // A distinct service target has its own address lookup.
                    if (!target.is_empty() && target != owner)
                        || (!hostname(owner) && qtype == TYPE_HTTPS)
                    {
                        return None;
                    }
                    if let Some(ech) = ech {
                        ech_names(ech, ttl, &mut values)?;
                    }
                }
                Data::Alias(_) => return None,
            }
        }
        values.retain(|value| value.ttl > 0);
        return Some(values);
    }
    None
}

pub(super) fn extract(
    epoch: u64,
    started_at_ms: u64,
    observed_at_ms: u64,
    qtype: u16,
    query: &[u8],
    answer: &[u8],
    synthesized: bool,
) -> Option<DeliveredDns> {
    let kind = match qtype {
        TYPE_A => DeliveredDnsKind::Ipv4,
        TYPE_AAAA => DeliveredDnsKind::Ipv6,
        TYPE_HTTPS | TYPE_SVCB => DeliveredDnsKind::Ech,
        _ => return None,
    };
    let mut query = Wire::new(query)?;
    let mut answer = Wire::new(answer)?;
    let flags = u16_at(answer.bytes, 2)?;
    let rcode = flags & 0x000f;
    if query.bytes[..2] != answer.bytes[..2]
        || query.bytes.len() > MAX_PACKET
        || u16_at(query.bytes, 2)? & !0x0130 != 0
        || flags & 0xf840 != 0x8000
        || !matches!(rcode, 0 | 2 | 3 | 5)
        || query.bytes[6..11] != [0; 5]
    {
        return None;
    }
    let (name, query_end) = query.question(qtype)?;
    match query.bytes[11] {
        0 if query_end == query.bytes.len() => (),
        1 => {
            let opt = query.record(query_end)?;
            if opt.kind != OPT || !opt.valid_opt() || opt.stop != query.bytes.len() {
                return None;
            }
        }
        _ => return None,
    }
    let (answered, at) = answer.question(qtype)?;
    if answered != name {
        return None;
    }
    let fully_delivered = !synthesized && flags & 0x0200 == 0 && answer.bytes.len() <= MAX_PACKET;
    let scoped_error = matches!(rcode, 2 | 5);
    let scope_known = fully_delivered && scoped_error && error_scope_known(&mut answer, at);
    let values = if fully_delivered && !scoped_error {
        answer_values(&mut answer, &name, qtype, rcode, at)
    } else {
        None
    };
    Some(DeliveredDns {
        epoch,
        started_at_ms,
        observed_at_ms,
        name,
        kind,
        qtype,
        incomplete: values.is_none(),
        scope_known,
        values: values.unwrap_or_default(),
    })
}

fn error_scope_known(answer: &mut Wire<'_>, at: usize) -> bool {
    // A bare SERVFAIL/REFUSED cannot speak for a CNAME target. A sole OPT
    // carries resolver metadata and may include an Extended DNS Error.
    match answer.bytes[6..12] {
        [0, 0, 0, 0, 0, 0] => at == answer.bytes.len(),
        [0, 0, 0, 0, 0, 1] => answer.record(at).is_some_and(|opt| {
            opt.kind == OPT && opt.valid_opt() && opt.stop == answer.bytes.len()
        }),
        _ => false,
    }
}

fn answer_values(
    answer: &mut Wire<'_>,
    name: &str,
    qtype: u16,
    rcode: u16,
    mut at: usize,
) -> Option<Vec<DeliveredDnsValue>> {
    // The common single address RR has no aliases or trailing sections.
    // The question has already been matched exactly and its first label is
    // at offset 12, so this fixed owner pointer needs no second name decode.
    let common_address_bytes = match qtype {
        TYPE_A => 4,
        TYPE_AAAA => 16,
        _ => 0,
    };
    if rcode == 0
        && common_address_bytes != 0
        && answer.bytes[6..12] == [0, 1, 0, 0, 0, 0]
        && answer.bytes.len() == at + 12 + common_address_bytes
        && answer.bytes[at..at + 2] == [0xc0, 12]
        && u16_at(answer.bytes, at + 2) == Some(qtype)
        && u16_at(answer.bytes, at + 4) == Some(IN)
        && u16_at(answer.bytes, at + 10) == Some(common_address_bytes as u16)
    {
        let ttl = effective_ttl(u32::from_be_bytes(
            answer.bytes[at + 6..at + 10].try_into().ok()?,
        ));
        if ttl == 0 {
            return Some(Vec::new());
        }
        let value = address_value(qtype, &answer.bytes[at + 12..])?;
        return Some(vec![DeliveredDnsValue { value, ttl }]);
    }
    let count = usize::from(u16_at(answer.bytes, 6)?);
    let authority_end = count + usize::from(u16_at(answer.bytes, 8)?);
    let total = authority_end + usize::from(u16_at(answer.bytes, 10)?);
    if total > MAX_RECORDS {
        return None;
    }

    let mut answers = Vec::with_capacity(count);
    let mut ns = false;
    let mut soa_owner = None;
    let mut opt = false;
    for index in 0..total {
        let record = answer.record(at)?;
        at = record.stop;
        if record.kind == OPT {
            if index < authority_end || opt || !record.valid_opt() {
                return None;
            }
            opt = true;
        }
        if index >= count {
            if index < authority_end {
                ns |= record.kind == TYPE_NS && record.class == IN;
                if record.kind == TYPE_SOA && record.class == IN {
                    let (_, second) = answer.name(record.data, record.stop, true)?;
                    let (_, tail) = answer.name(second, record.stop, true)?;
                    if tail + 20 != record.stop || soa_owner.replace(record.owner).is_some() {
                        return None;
                    }
                }
            }
            continue;
        }
        if record.kind == TYPE_DNAME {
            return None;
        }
        if record.kind != qtype && record.kind != TYPE_CNAME {
            continue;
        }
        if record.class != IN || record.owner.is_empty() {
            return None;
        }
        let data = match record.kind {
            TYPE_CNAME => {
                let (target, end) = answer.name(record.data, record.stop, true)?;
                if target.is_empty() || end != record.stop {
                    return None;
                }
                Data::Alias(target)
            }
            TYPE_A | TYPE_AAAA => Data::Address(record.body),
            _ => {
                let priority = u16_at(record.body, 0)?;
                let (target, end) = answer.name(record.data + 2, record.stop, false)?;
                let params = answer.bytes.get(end..record.stop)?;
                if priority == 0 && (!params.is_empty() || target.is_empty()) {
                    return None;
                }
                if !target.is_empty() && !hostname(&target) {
                    return None;
                }
                Data::Service {
                    target,
                    priority,
                    params,
                }
            }
        };
        answers.push((record, data));
    }
    if at != answer.bytes.len() || (ns && soa_owner.is_none()) {
        return None;
    }
    rrset_values(&answers, name, qtype, rcode, soa_owner.as_deref())
}
