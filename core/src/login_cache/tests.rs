use super::*;
use std::fs;
use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};

const HOST: &str = "vpn.example";
const FIRST: &str = "192.0.2.1";
const SECOND: &str = "2001:db8::2";

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(temporary_name().unwrap().to_str().unwrap());
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn connected_peers_are_private_scoped_and_ordered() {
    let dir = Scratch::new();
    assert!(lookup(&dir.0, HOST, 443).is_empty());
    remember(&dir.0, "VPN.EXAMPLE.", 443, FIRST).unwrap();
    remember(&dir.0, HOST, 443, SECOND).unwrap();
    assert_eq!(lookup(&dir.0, HOST, 443), [SECOND, FIRST]);
    assert!(lookup(&dir.0, HOST, 8443).is_empty());
    assert!(lookup(&dir.0, "other.example", 443).is_empty());
    remember(&dir.0, HOST, 443, "::ffff:192.0.2.1").unwrap();
    assert_eq!(lookup(&dir.0, HOST, 443), [FIRST, SECOND]);
    let metadata = fs::metadata(dir.0.join(FILE.to_str().unwrap())).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert!(remember(&dir.0, HOST, 443, "vpn.example").is_err());
    assert!(remember(&dir.0, HOST, 443, "0.0.0.0").is_err());
    assert!(remember(&dir.0, HOST, 0, FIRST).is_err());
}

#[test]
fn bounded_cache_expires_each_address_and_keeps_recent_gateways() {
    let mut cache = Cache::default();
    let key = Gateway::new(HOST, 443).unwrap();
    let now = ADDRESS_TTL.as_secs() + 100;
    cache.record(key.clone(), parse_address(FIRST).unwrap(), now);
    cache.record(key.clone(), parse_address(SECOND).unwrap(), now + 1);
    assert_eq!(cache.addresses(&key, now), [FIRST]); // Future record is unusable.
    assert_eq!(cache.addresses(&key, now + ADDRESS_TTL.as_secs()), [SECOND]);
    for octet in 2..=12 {
        let peer = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, octet));
        cache.record(key.clone(), peer, now + 2);
    }
    assert_eq!(cache.addresses(&key, now + 2).len(), MAX_ADDRESSES);
    assert_eq!(
        cache.addresses(&key, now + 2).first().unwrap(),
        "192.0.2.12"
    );
    assert!(!cache.addresses(&key, now + 2).contains(&FIRST.to_string()));
    for index in 0..MAX_GATEWAYS {
        let gateway = Gateway::new(&format!("vpn-{index}.example"), 443).unwrap();
        cache.record(gateway, parse_address(FIRST).unwrap(), now + 3);
    }
    assert_eq!(cache.gateways.len(), MAX_GATEWAYS);
    assert!(cache.addresses(&key, now + 3).is_empty());
}

#[test]
fn unsafe_and_corrupt_files_never_supply_addresses() {
    let dir = Scratch::new();
    let cache = dir.0.join(FILE.to_str().unwrap());
    let other = dir.0.join("unrelated");
    fs::write(&other, b"unrelated").unwrap();
    symlink(&other, &cache).unwrap();
    assert!(lookup(&dir.0, HOST, 443).is_empty());
    assert!(remember(&dir.0, HOST, 443, FIRST).is_err());
    assert_eq!(fs::read(&other).unwrap(), b"unrelated");
    fs::remove_file(&cache).unwrap();
    remember(&dir.0, HOST, 443, FIRST).unwrap();
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(lookup(&dir.0, HOST, 443).is_empty());
    assert!(remember(&dir.0, HOST, 443, FIRST).is_err());
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&cache, vec![b' '; MAX_FILE_BYTES + 1]).unwrap();
    assert!(lookup(&dir.0, HOST, 443).is_empty());
    remember(&dir.0, HOST, 443, SECOND).unwrap();
    assert_eq!(lookup(&dir.0, HOST, 443), [SECOND]);
    fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(lookup(&dir.0, HOST, 443).is_empty());
}

#[test]
fn concurrent_records_preserve_each_successful_peer() {
    let dir = Scratch::new();
    std::thread::scope(|threads| {
        for octet in 1..=MAX_ADDRESSES {
            let path = &dir.0;
            threads.spawn(move || remember(path, HOST, 443, &format!("192.0.2.{octet}")).unwrap());
        }
    });
    assert_eq!(lookup(&dir.0, HOST, 443).len(), MAX_ADDRESSES);
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
}

#[test]
fn intent_consumes_only_fresh_matching_tls_result_and_never_writes_disk() {
    let dir = Scratch::new();
    let now = Instant::now();
    let key = Gateway::new(HOST, 443).unwrap();
    let mut prep = Preparation::default();
    assert!(prep.begin(key.clone(), now).is_none());
    prep.confirm_direct();
    let request = prep.begin(key.clone(), now).unwrap();
    let address = PreparedGateway::Address(parse_address(FIRST).unwrap());
    prep.finish(request, Some(address), now);
    assert_eq!(prep.take_for_intent(Some(&key), now), Some(address));
    assert_eq!(prep.take_for_intent(Some(&key), now), None);
    assert!(prep.begin(key.clone(), now).is_none());
    assert!(lookup(&dir.0, HOST, 443).is_empty());

    prep.confirm_direct();
    let request = prep.begin(key.clone(), now).unwrap();
    prep.finish(request, Some(address), now);
    let other_port = Gateway::new(HOST, 8443).unwrap();
    assert_eq!(prep.take_for_intent(Some(&other_port), now), None);

    prep.confirm_direct();
    let request = prep.begin(key.clone(), now).unwrap();
    prep.finish(request, Some(address), now);
    assert_eq!(
        prep.take_for_intent(Some(&key), now + PREPARATION_TTL),
        None
    );
}

#[test]
fn cancelled_late_timed_out_and_failed_tls_results_are_discarded() {
    let now = Instant::now();
    let key = Gateway::new(HOST, 443).unwrap();
    let mut prep = Preparation::default();
    prep.confirm_direct();
    let old = prep.begin(key.clone(), now).unwrap();
    assert_eq!(prep.take_for_intent(Some(&key), now), None);
    let rejected = Some(PreparedGateway::CertificateRejected);
    prep.finish(old, rejected, now);
    assert_eq!(prep.take_for_intent(Some(&key), now), None);

    prep.confirm_direct();
    let newer = prep.begin(key.clone(), now).unwrap();
    prep.finish(old, rejected, now);
    prep.finish(newer, None, now); // Transport failed without a trust rejection.
    assert_eq!(prep.take_for_intent(Some(&key), now), None);

    prep.confirm_direct();
    let timed = prep.begin(key.clone(), now).unwrap();
    prep.finish(timed, rejected, now + PROBE_BUDGET);
    assert_eq!(prep.take_for_intent(Some(&key), now + PROBE_BUDGET), None);
}

#[test]
fn trust_rejection_is_one_use_bound_to_target_and_expires() {
    let dir = Scratch::new();
    let now = Instant::now();
    let key = Gateway::new(HOST, 443).unwrap();
    let other_host = Gateway::new("another.example", 443).unwrap();
    let other_port = Gateway::new(HOST, 8443).unwrap();
    let mut prep = Preparation::default();
    let rejected = Some(PreparedGateway::CertificateRejected);

    prep.confirm_direct();
    let request = prep.begin(key.clone(), now).unwrap();
    prep.finish(request, rejected, now);
    assert_eq!(prep.take_for_intent(Some(&key), now), rejected);
    assert_eq!(prep.take_for_intent(Some(&key), now), None);
    assert!(lookup(&dir.0, HOST, 443).is_empty());

    for other in [Some(&other_host), Some(&other_port), None] {
        prep.confirm_direct();
        let request = prep.begin(key.clone(), now).unwrap();
        prep.finish(request, rejected, now);
        assert_eq!(prep.take_for_intent(other, now), None);
        assert_eq!(prep.take_for_intent(Some(&key), now), None);
    }

    prep.confirm_direct();
    let request = prep.begin(key.clone(), now).unwrap();
    prep.finish(request, rejected, now);
    assert_eq!(
        prep.take_for_intent(Some(&key), now + PREPARATION_TTL),
        None
    );
}

#[test]
fn fresh_preparation_replaces_prior_trust_rejection() {
    let now = Instant::now();
    let key = Gateway::new(HOST, 443).unwrap();
    let mut prep = Preparation::default();
    prep.confirm_direct();
    let old = prep.begin(key.clone(), now).unwrap();
    prep.finish(old, Some(PreparedGateway::CertificateRejected), now);
    let new = prep.begin(key.clone(), now).unwrap();
    prep.finish(old, Some(PreparedGateway::CertificateRejected), now);
    let address = PreparedGateway::Address(parse_address(FIRST).unwrap());
    prep.finish(new, Some(address), now);
    assert_eq!(prep.take_for_intent(Some(&key), now), Some(address));
}

#[test]
fn preparation_status_observes_the_target_without_consuming_the_result() {
    let now = Instant::now();
    let key = Gateway::new(HOST, 443).unwrap();
    let other = Gateway::new(HOST, 8443).unwrap();
    let mut prep = Preparation::default();
    assert_eq!(prep.status(&key, now), PreparationStatus::Idle);

    prep.confirm_direct();
    let request = prep.begin(key.clone(), now).unwrap();
    assert_eq!(prep.status(&key, now), PreparationStatus::Preparing);
    assert_eq!(prep.status(&other, now), PreparationStatus::Idle);
    let address = PreparedGateway::Address(parse_address(FIRST).unwrap());
    prep.finish(request, Some(address), now);
    assert_eq!(prep.status(&key, now), PreparationStatus::Ready);
    assert_eq!(
        prep.status(&key, now + PREPARATION_TTL),
        PreparationStatus::Idle
    );
    assert_eq!(prep.take_for_intent(Some(&key), now), Some(address));
    assert_eq!(prep.status(&key, now), PreparationStatus::Idle);
}

#[test]
fn preparation_status_distinguishes_rejection_from_unavailable() {
    let now = Instant::now();
    let key = Gateway::new(HOST, 443).unwrap();
    let mut prep = Preparation::default();
    prep.confirm_direct();
    let request = prep.begin(key.clone(), now).unwrap();
    prep.finish(request, Some(PreparedGateway::CertificateRejected), now);
    assert_eq!(
        prep.status(&key, now),
        PreparationStatus::CertificateRejected
    );
    let retry = prep.begin(key.clone(), now).unwrap();
    assert_eq!(prep.status(&key, now), PreparationStatus::Preparing);
    assert_eq!(
        prep.status(&key, now + PROBE_BUDGET),
        PreparationStatus::TimedOut
    );
    prep.finish(retry, None, now + PROBE_BUDGET);
    assert_eq!(
        prep.status(&key, now + PROBE_BUDGET),
        PreparationStatus::Unavailable
    );
    assert_eq!(prep.take_for_intent(Some(&key), now + PROBE_BUDGET), None);
    assert_eq!(
        prep.status(&key, now + PROBE_BUDGET),
        PreparationStatus::Idle
    );
}
