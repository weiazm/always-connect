//! Site lists kept current (DESIGN.md §66.30): the App downloads the
//! published `dlc.dat` of v2fly/domain-list-community (the same project
//! the bundled lists come from) and hands the bytes here. This module
//! reads that protobuf file and writes the bundled text format
//! (scripts/make-geo-data.py), so the App's reader stays one format:
//!
//! ```text
//! [name]
//! d:example.com          domain and subdomains
//! f:www.example.com      this name only
//! k:example              keyword
//! r:^a\d+\.example\.com$ regular expression
//! d:ads.example.com @ads attributes follow, sorted
//! ```
//!
//! The published file already has includes and affiliations resolved.
//! A file that does not decode, or decodes to far fewer lists than the
//! project has, is refused: the App then keeps what it had.

use std::collections::{BTreeMap, HashSet};

/// The project has well over a thousand lists; a file with fewer than
/// this is a truncated or foreign download, not a smaller catalogue.
pub const MIN_LISTS: usize = 500;
const MIN_RULES: usize = 20_000;

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, at: 0 }
    }

    fn varint(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self.data.get(self.at)?;
            self.at += 1;
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    /// The next (field number, value); None at the end, Err on damage.
    fn next(&mut self) -> Result<Option<(u64, Field<'a>)>, ()> {
        if self.at >= self.data.len() {
            return Ok(None);
        }
        let key = self.varint().ok_or(())?;
        let field = key >> 3;
        let value = match key & 7 {
            0 => Field::Varint(self.varint().ok_or(())?),
            1 => {
                self.at = self.at.checked_add(8).filter(|&end| end <= self.data.len()).ok_or(())?;
                Field::Varint(0)
            }
            2 => {
                let len = usize::try_from(self.varint().ok_or(())?).map_err(|_| ())?;
                let end = self.at.checked_add(len).filter(|&end| end <= self.data.len()).ok_or(())?;
                let bytes = &self.data[self.at..end];
                self.at = end;
                Field::Bytes(bytes)
            }
            5 => {
                self.at = self.at.checked_add(4).filter(|&end| end <= self.data.len()).ok_or(())?;
                Field::Varint(0)
            }
            _ => return Err(()),
        };
        Ok(Some((field, value)))
    }
}

fn text(bytes: &[u8]) -> Result<&str, ()> {
    std::str::from_utf8(bytes).map_err(|_| ())
}

/// One Domain message as a text line; None for a kind this format lacks.
fn rule(bytes: &[u8]) -> Result<Option<String>, ()> {
    let mut kind = 0u64;
    let mut value = "";
    let mut attributes = Vec::new();
    let mut reader = Reader::new(bytes);
    while let Some((field, item)) = reader.next()? {
        match (field, item) {
            (1, Field::Varint(v)) => kind = v,
            (2, Field::Bytes(b)) => value = text(b)?,
            (3, Field::Bytes(b)) => {
                let mut attribute = Reader::new(b);
                while let Some((field, item)) = attribute.next()? {
                    if let (1, Field::Bytes(key)) = (field, item) {
                        attributes.push(text(key)?.to_ascii_lowercase());
                    }
                }
            }
            _ => {}
        }
    }
    // routercommon.Domain.Type: Plain (keyword), Regex, RootDomain, Full.
    let prefix = match kind {
        0 => "k:",
        1 => "r:",
        2 => "d:",
        3 => "f:",
        _ => return Ok(None),
    };
    let value = if kind == 1 { value.to_owned() } else { value.to_ascii_lowercase() };
    // A line break inside a value would start a new line in the text.
    if value.is_empty() || value.contains(['\n', '\r', ' ']) {
        return Ok(None);
    }
    attributes.retain(|a| !a.is_empty() && a.bytes().all(|b| b.is_ascii_graphic()));
    attributes.sort();
    attributes.dedup();
    let mut line = format!("{prefix}{value}");
    for attribute in attributes {
        line.push_str(" @");
        line.push_str(&attribute);
    }
    Ok(Some(line))
}

/// `dlc.dat` (routercommon.GeoSiteList) to the bundled text format.
pub fn from_dlc(data: &[u8]) -> Result<String, &'static str> {
    let damaged = |_| "清单文件损坏";
    let mut lists: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut reader = Reader::new(data);
    while let Some((field, item)) = reader.next().map_err(damaged)? {
        let (1, Field::Bytes(entry)) = (field, item) else { continue };
        let mut name = None;
        let mut rules = Vec::new();
        let mut site = Reader::new(entry);
        while let Some((field, item)) = site.next().map_err(damaged)? {
            match (field, item) {
                (1, Field::Bytes(b)) => name = Some(text(b).map_err(damaged)?.to_ascii_lowercase()),
                (2, Field::Bytes(b)) => {
                    if let Some(line) = rule(b).map_err(damaged)? {
                        rules.push(line);
                    }
                }
                _ => {}
            }
        }
        let Some(name) = name.filter(|n| {
            !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-!".contains(&b))
        }) else {
            continue;
        };
        lists.entry(name).or_default().extend(rules);
    }
    let total: usize = lists.values().map(Vec::len).sum();
    if lists.len() < MIN_LISTS || total < MIN_RULES {
        return Err("清单数量不对");
    }
    let mut out = String::with_capacity(total * 24);
    for (name, rules) in &lists {
        out.push('[');
        out.push_str(name);
        out.push_str("]\n");
        let mut seen = HashSet::new();
        for line in rules {
            if seen.insert(line.as_str()) {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn bytes(field: u64, value: &[u8], out: &mut Vec<u8>) {
        varint(field << 3 | 2, out);
        varint(value.len() as u64, out);
        out.extend_from_slice(value);
    }

    fn domain(kind: u64, value: &str, attributes: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        varint(1 << 3, &mut out);
        varint(kind, &mut out);
        bytes(2, value.as_bytes(), &mut out);
        for a in attributes {
            let mut attribute = Vec::new();
            bytes(1, a.as_bytes(), &mut attribute);
            varint(2 << 3, &mut attribute);
            varint(1, &mut attribute);
            bytes(3, &attribute, &mut out);
        }
        out
    }

    fn site(name: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        bytes(1, name.as_bytes(), &mut out);
        for d in domains {
            bytes(2, d, &mut out);
        }
        out
    }

    fn catalogue(extra: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for s in extra {
            bytes(1, s, &mut out);
        }
        for i in 0..MIN_LISTS {
            let domains: Vec<_> = (0..MIN_RULES / MIN_LISTS + 1)
                .map(|j| domain(2, &format!("d{j}.l{i}.example"), &[]))
                .collect();
            bytes(1, &site(&format!("LIST{i:04}"), &domains), &mut out);
        }
        out
    }

    #[test]
    fn every_rule_kind_and_attribute_becomes_the_bundled_text() {
        let first = site("EXAMPLE", &[
            domain(2, "Example.com", &[]),
            domain(3, "WWW.example.net", &["cn"]),
            domain(0, "example", &[]),
            domain(1, r"^a\d+\.Example\.org$", &[]),
            domain(2, "ads.example.com", &["telemetry", "ads"]),
            domain(2, "example.com", &[]),
            domain(9, "unknown.example", &[]),
        ]);
        let text = from_dlc(&catalogue(&[first])).unwrap();
        let list: Vec<_> = text.split("[example]\n").nth(1).unwrap().lines()
            .take_while(|l| !l.starts_with('[')).collect();
        assert_eq!(list, [
            "d:example.com",
            "f:www.example.net @cn",
            "k:example",
            r"r:^a\d+\.Example\.org$",
            "d:ads.example.com @ads @telemetry",
        ]);
        assert!(text.starts_with("[example]\n"), "names sorted, lower case");
    }

    #[test]
    fn short_damaged_or_foreign_files_are_refused() {
        let one = site("example", &[domain(2, "example.com", &[])]);
        let mut small = Vec::new();
        bytes(1, &one, &mut small);
        assert!(from_dlc(&small).is_err());
        let mut cut = catalogue(&[]);
        cut.truncate(cut.len() - 3);
        assert!(from_dlc(&cut).is_err());
        assert!(from_dlc(b"<html>rate limited</html>").is_err());
        assert!(from_dlc(&[]).is_err());
    }

    #[test]
    fn values_that_would_break_the_text_format_are_dropped() {
        let bad = site("x", &[domain(2, "a.example\n[y]", &[]), domain(2, "b.example", &[])]);
        let text = from_dlc(&catalogue(&[bad])).unwrap();
        assert!(!text.contains("[y]"));
        assert!(text.contains("[x]\nd:b.example\n"));
    }

    /// `ALWAYSCONNECT_DLC=<dlc.dat> cargo test -- --ignored real_dlc`
    #[test]
    #[ignore]
    fn real_dlc() {
        let data = std::fs::read(std::env::var("ALWAYSCONNECT_DLC").unwrap()).unwrap();
        let text = from_dlc(&data).unwrap();
        std::fs::write(std::env::var("ALWAYSCONNECT_DLC_OUT").unwrap(), text).unwrap();
    }
}
