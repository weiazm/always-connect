use super::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn direct(text: &str) -> SourceEvidence {
    SourceEvidence::Direct(text.parse().unwrap())
}

fn policy(enabled: bool, ranges: &[&str]) -> SourcePolicy {
    SourcePolicy::from_config(
        enabled,
        &ranges.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    )
    .unwrap()
}

#[test]
fn legacy_group_decodes_to_country_only_policy() {
    // The app's existing Group owns these flat fields. The compiled policy
    // only receives the values and never serializes its own config shape.
    #[derive(Default, Deserialize, Serialize)]
    #[serde(default, rename_all = "camelCase")]
    struct Group {
        enabled: bool,
        expect: Vec<String>,
        cidrs: Vec<String>,
        exit_range_check: bool,
        exit_ranges: Vec<String>,
    }
    let old = json!({ "enabled": true, "expect": ["SG"], "cidrs": ["203.0.113.0/24"] });
    let group: Group = serde_json::from_value(old).unwrap();
    assert!(!group.exit_range_check && group.exit_ranges.is_empty());
    let compiled = SourcePolicy::from_config(group.exit_range_check, &group.exit_ranges).unwrap();
    assert_eq!(
        compiled.evaluate(direct("192.0.2.34")),
        SourceDecision::Disabled
    );
    assert_eq!(
        compiled.evaluate(SourceEvidence::Unverified),
        SourceDecision::Disabled
    );
    let encoded: Value = serde_json::to_value(group).unwrap();
    assert_eq!(encoded["exitRangeCheck"], false);
    assert_eq!(encoded["exitRanges"], json!([]));
    assert_eq!(encoded["cidrs"], json!(["203.0.113.0/24"]));
    assert!(encoded.get("learnNetworks").is_none());
    assert!(encoded.get("sourcePolicy").is_none());

    let group: Group = serde_json::from_value(json!({
        "enabled": true, "expect": ["SG"], "cidrs": ["203.0.113.0/24"],
        "exitRangeCheck": true, "exitRanges": ["192.0.2.0/24"]
    }))
    .unwrap();
    let compiled = SourcePolicy::from_config(group.exit_range_check, &group.exit_ranges).unwrap();
    assert_eq!(
        compiled.evaluate(direct("192.0.2.34")),
        SourceDecision::Allowed
    );
    assert_eq!(
        compiled.evaluate(direct("203.0.113.34")),
        SourceDecision::Unrecognized
    );
}

#[test]
fn only_an_allowed_direct_source_passes_an_enabled_policy() {
    let rule = policy(true, &["192.0.2.0/24", "2001:db8:1::/64"]);
    for address in [
        "192.0.2.0",
        "192.0.2.122",
        "192.0.2.255",
        "2001:db8:1::abcd",
    ] {
        assert_eq!(
            rule.evaluate(direct(address)),
            SourceDecision::Allowed,
            "{address}"
        );
    }
    for address in ["192.0.3.1", "2001:db8:2::1", "::ffff:192.0.2.122"] {
        assert_eq!(
            rule.evaluate(direct(address)),
            SourceDecision::Unrecognized,
            "{address}"
        );
    }
    assert_eq!(
        rule.evaluate(SourceEvidence::Unverified),
        SourceDecision::NoDirectAddress
    );
    assert_eq!(
        rule.evaluate(direct("::ffff:127.0.0.1")),
        SourceDecision::NoDirectAddress
    );
    assert_eq!(
        rule.evaluate(direct("0.0.0.0")),
        SourceDecision::NoDirectAddress
    );
    assert_eq!(
        policy(true, &[]).evaluate(direct("192.0.2.1")),
        SourceDecision::Unrecognized
    );
    assert_eq!(
        policy(false, &["malformed"]).evaluate(direct("192.0.2.1")),
        SourceDecision::Disabled
    );
}

#[test]
fn bare_addresses_allow_only_that_single_address_and_family() {
    let rule = policy(
        true,
        &["192.0.2.19", "2001:0DB8::19/128", "::ffff:198.51.100.5"],
    );
    for address in ["192.0.2.19", "2001:db8::19", "::ffff:198.51.100.5"] {
        assert_eq!(rule.evaluate(direct(address)), SourceDecision::Allowed);
    }
    for address in ["192.0.2.18", "2001:db8::18", "198.51.100.5"] {
        assert_eq!(rule.evaluate(direct(address)), SourceDecision::Unrecognized);
    }
    assert_eq!(
        "192.0.2.19".parse::<SourcePrefix>().unwrap().to_string(),
        "192.0.2.19/32"
    );
    assert_eq!(
        "2001:0DB8::19/128"
            .parse::<SourcePrefix>()
            .unwrap()
            .to_string(),
        "2001:db8::19/128"
    );
}

#[test]
fn explicit_prefixes_are_canonical_and_malformed_rules_are_rejected() {
    for text in ["192.0.2.7/24", "2001:db8::1/64"] {
        assert_eq!(
            text.parse::<SourcePrefix>(),
            Err(SourcePrefixError::HostBitsSet)
        );
        assert!(SourcePolicy::from_config(true, &["192.0.2.3".into(), text.into()]).is_err());
    }
    for text in [
        "192.0.2.0/33",
        "2001:db8::/129",
        "192.0.2.0/",
        "192.0.2.0/+24",
        "2001:db8::/64/1",
    ] {
        assert_eq!(
            text.parse::<SourcePrefix>(),
            Err(SourcePrefixError::InvalidLength)
        );
    }
    assert_eq!(
        "vpn.example/24".parse::<SourcePrefix>(),
        Err(SourcePrefixError::InvalidAddress)
    );
    let v4 = "0.0.0.0/0".parse::<SourcePrefix>().unwrap();
    let v6 = "::/0".parse::<SourcePrefix>().unwrap();
    assert!(v4.contains("192.0.2.5".parse().unwrap()));
    assert!(!v4.contains("2001:db8::5".parse().unwrap()));
    assert!(v6.contains("2001:db8::5".parse().unwrap()));
    assert!(!v6.contains("192.0.2.5".parse().unwrap()));
}

#[test]
fn learning_reports_one_observed_address_and_an_optional_review_choice() {
    assert!(SourceSuggestion::from_evidence(SourceEvidence::Unverified, true).is_none());
    assert!(SourceSuggestion::from_evidence(direct("::"), true).is_none());
    let original = policy(true, &["192.0.2.9"]);
    let observed = direct("192.0.2.35");
    let proposal = SourceSuggestion::from_evidence(observed, true).unwrap();
    assert_eq!(
        serde_json::to_value(&proposal).unwrap(),
        json!({
            "address": "192.0.2.35", "suggestedPrefix": "192.0.2.0/24"
        })
    );
    assert_eq!(original.evaluate(observed), SourceDecision::Unrecognized);
    let exact = policy(true, &["192.0.2.9", "192.0.2.35"]);
    assert_eq!(
        exact.evaluate(direct("192.0.2.36")),
        SourceDecision::Unrecognized
    );
    let confirmed = policy(true, &["192.0.2.0/24"]);
    assert_eq!(
        confirmed.evaluate(direct("192.0.2.36")),
        SourceDecision::Allowed
    );

    for (address, learn_networks) in [
        ("192.0.2.35", false),
        ("2001:db8::35", true),
        ("::ffff:192.0.2.35", true),
    ] {
        let suggestion = SourceSuggestion::from_evidence(direct(address), learn_networks).unwrap();
        assert!(suggestion.suggested_prefix.is_none());
        assert_eq!(suggestion.address, address.parse::<IpAddr>().unwrap());
    }
    assert_eq!(
        SourceDecision::Unrecognized.failure_reason(),
        Some("exit-range-mismatch")
    );
    assert_eq!(
        SourceDecision::NoDirectAddress.failure_reason(),
        Some("exit-ip-unavailable")
    );
    assert_eq!(SourceDecision::Allowed.failure_reason(), None);
}
