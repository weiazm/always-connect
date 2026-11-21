use super::*;
use std::collections::VecDeque;

fn kernel(read: &[&str], stdout: &str) -> (Vec<String>, Result<PfOutput, ()>) {
    (
        read.iter().map(|arg| (*arg).to_owned()).collect(),
        Ok(PfOutput {
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }),
    )
}

fn main_rules(text: &str) -> (Vec<String>, Result<PfOutput, ()>) {
    kernel(&["-s", "rules"], text)
}

fn anchor_rules(path: &str, text: &str) -> (Vec<String>, Result<PfOutput, ()>) {
    kernel(&["-a", path, "-s", "rules"], text)
}

fn run_steps<T>(
    steps: impl IntoIterator<Item = (Vec<String>, Result<PfOutput, ()>)>,
    action: impl FnOnce(&mut dyn FnMut(&[&str]) -> Result<PfOutput, ()>) -> T,
) -> T {
    let mut steps = VecDeque::from_iter(steps);
    let result = action(&mut |args| {
        let (expected, output) = steps
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected pfctl call {args:?}"));
        assert_eq!(args, expected);
        output
    });
    assert!(steps.is_empty(), "expected another pfctl call");
    result
}

#[test]
fn wildcard_children_follow_kernel_order_and_later_rules_are_irrelevant() {
    let steps = [
        main_rules(
            "scrub-anchor \"com.apple/*\" all fragment reassemble\n\
                    anchor \"vendor.vpn\" all\nanchor \"com.apple/*\" all\npass out quick all",
        ),
        anchor_rules(
            "vendor.vpn",
            "block in quick all\npass out all label \"decoy quick text\"",
        ),
        kernel(
            &["-a", "com.apple", "-s", "Anchors"],
            "400.Later\ncom.apple/300.AlwaysConnect\n100.Earlier",
        ),
        anchor_rules("com.apple/100.Earlier", "block out all"),
    ];
    assert_eq!(run_steps(steps, |run| verify_rule_chain(run)), Ok(()));
}

#[test]
fn detects_quick_pass_in_main_vendor_and_earlier_wildcard_child() {
    let main = "anchor \"vendor.vpn\" all\nanchor \"com.apple/*\" all";
    for steps in [
        vec![main_rules(
            "pass out log (all) quick on en0 all\nanchor \"com.apple/*\" all",
        )],
        vec![main_rules("pass in quick all\nanchor \"com.apple/*\" all")],
        vec![
            main_rules(main),
            anchor_rules("vendor.vpn", "pass quick inet all"),
        ],
        vec![
            main_rules(main),
            anchor_rules("vendor.vpn", ""),
            kernel(
                &["-a", "com.apple", "-s", "Anchors"],
                "300.AlwaysConnect\n100.Earlier",
            ),
            anchor_rules("com.apple/100.Earlier", "anchor \"Nested\" all"),
            anchor_rules("com.apple/100.Earlier/Nested", "pass out quick all"),
        ],
    ] {
        assert_eq!(
            run_steps(steps, |run| verify_rule_chain(run)),
            Err(RuleChainError::EarlierQuickPass)
        );
    }
}

#[test]
fn rules_require_a_reachable_unconditional_anchor_and_successful_reads() {
    for (text, expected) in [
        ("pass out all", Err(RuleChainError::AnchorUnreachable)),
        (
            "anchor \"com.apple/300.AlwaysConnect\" out on en0 all",
            Err(RuleChainError::UnrecognizedRules),
        ),
        (
            "anchor \"com.apple/300.AlwaysConnect\" in all",
            Err(RuleChainError::UnrecognizedRules),
        ),
        (
            "block drop out quick all",
            Err(RuleChainError::EarlierQuickBlock),
        ),
        (
            "anchor \"/com.apple/300.AlwaysConnect\" out from any to any",
            Ok(()),
        ),
    ] {
        assert_eq!(
            run_steps([main_rules(text)], |run| verify_rule_chain(run)),
            expected
        );
    }
    assert_eq!(
        run_steps(
            [
                main_rules("anchor \"com.apple\" all"),
                anchor_rules("com.apple", "anchor \"300.AlwaysConnect\" all"),
            ],
            |run| verify_rule_chain(run)
        ),
        Ok(())
    );
    assert_eq!(
        run_steps(
            [
                main_rules("anchor \"com.apple\" all"),
                anchor_rules("com.apple", "anchor \"*\" all"),
                kernel(&["-a", "com.apple", "-s", "Anchors"], ""),
            ],
            |run| verify_rule_chain(run)
        ),
        Err(RuleChainError::AnchorUnreachable)
    );
    assert_eq!(
        verify_rule_chain(|_| Err::<PfOutput, _>(())),
        Err(RuleChainError::ReadFailed)
    );
}

fn policy(carrier_udp: bool) -> BlockingPolicy {
    BlockingPolicy::new(
        "en0",
        &["203.0.113.1".into(), "2001:db8:1::1".into()],
        443,
        carrier_udp,
        &["192.0.2.0/24".into(), "2001:db8:2::/64".into()],
    )
    .unwrap()
}

fn row(id: u64, head: &str) -> String {
    format!(
        "{head}\n   age 00:00:01, expires in 00:02:00, 0:0 pkts, 0:0 bytes, rule 8\n\
             \x20  id: {id:016x} creatorid: 00000001\n"
    )
}

fn states(rows: &str) -> (Vec<String>, Result<PfOutput, ()>) {
    kernel(&["-vv", "-s", "states"], rows)
}

fn kill(
    interface: &str,
    from: &str,
    to: &str,
    killed: usize,
) -> (Vec<String>, Result<PfOutput, ()>) {
    (["-i", interface, "-k", from, "-k", to].map(str::to_owned).to_vec(), Ok(PfOutput {
        stdout: String::new(),
        stderr: format!("No ALTQ support in kernel\nkilled {killed} states from 1 sources and 1 destinations\n"),
    }))
}

#[test]
fn preserves_bound_loopback_and_exact_outbound_allowances() {
    let permitted = [
        "lo0 tcp 127.0.0.1:54000 -> 127.0.0.1:8000 ESTABLISHED:ESTABLISHED",
        "en0 tcp 192.0.2.2:54000 -> 203.0.113.1:443 ESTABLISHED:ESTABLISHED",
        "en0 udp 2001:db8:2::2[54000] -> 2001:db8:1::1[443] MULTIPLE:MULTIPLE",
        "en0 tcp 192.0.2.2:54000 -> 192.0.2.4:22 ESTABLISHED:ESTABLISHED",
        "en0 udp 0.0.0.0:68 -> 255.255.255.255:67 SINGLE:NO_TRAFFIC",
        "en0 udp 192.0.2.2:5353 -> 224.0.0.251:5353 SINGLE:NO_TRAFFIC",
        "en0 udp fe80::1%en0[5353] -> ff02::fb[5353] SINGLE:NO_TRAFFIC",
        "en0 udp fe80::2[546] -> ff02::1:2[547] SINGLE:NO_TRAFFIC",
        "en0 icmp6 fe80::1 -> ff02::1 0:0",
        "en0 tcp [fe80::1]:60000 -> [fe80::2]:22 ESTABLISHED:ESTABLISHED",
    ]
    .iter()
    .enumerate()
    .map(|(i, head)| row(i as u64 + 1, head))
    .collect::<String>();
    assert_eq!(
        run_steps([states(&permitted)], |run| clear_states(&policy(true), run)),
        Ok(())
    );
    assert_eq!(
        run_steps([states(&permitted)], |run| check_states(
            &policy(false),
            run
        )),
        Err(StateError::BlockedStateRemains)
    );
}

#[test]
fn cleans_only_unique_bound_blocked_state_and_reads_back() {
    let allowed = row(
        1,
        "lo0 tcp 127.0.0.1:54001 -> 127.0.0.1:443 ESTABLISHED:ESTABLISHED",
    );
    let blocked = row(
        2,
        "en0 tcp 192.0.2.2:54000 -> 198.51.100.1:443 ESTABLISHED:ESTABLISHED",
    );
    let before = format!("{allowed}{blocked}");
    assert_eq!(
        run_steps(
            [
                states(&before),
                states(&before),
                kill("en0", "192.0.2.2", "198.51.100.1", 1),
                states(&allowed),
            ],
            |run| clear_states(&policy(false), run)
        ),
        Ok(())
    );
}

#[test]
fn existing_unverified_tunnel_is_retained_but_never_confirms_a_cold_login() {
    let active = row(3, "utun2 tcp 192.0.2.2:54001 -> 198.51.100.1:443 ESTABLISHED:ESTABLISHED");
    assert_eq!(run_steps([states(&active)], |run| clear_states(&policy(false), run)),
               Err(StateError::UnknownInterface));
}

#[test]
fn dns_barrier_precedes_lan_gateway_and_link_local_permissions() {
    for remote in ["192.0.2.4:53", "203.0.113.1:53", "fe80::1[53]"] {
        let local = if remote.contains('[') {
            "2001:db8:2::2[60000]"
        } else {
            "192.0.2.2:60000"
        };
        let content = row(1, &format!("en0 udp {local} -> {remote} SINGLE:NO_TRAFFIC"));
        assert_eq!(
            run_steps([states(&content)], |run| check_states(&policy(true), run)),
            Err(StateError::BlockedStateRemains)
        );
    }
}

#[test]
fn selector_reverses_inbound_and_canonicalizes_ipv6() {
    let content = row(
        1,
        "en0 tcp 2001:0db8:2::2[54000] <- 2001:db8:3::1[33] ESTABLISHED:ESTABLISHED",
    );
    assert_eq!(
        run_steps(
            [
                states(&content),
                states(&content),
                kill("en0", "2001:db8:3::1", "2001:db8:2::2", 1),
                states(""),
            ],
            |run| clear_states(&policy(false), run)
        ),
        Ok(())
    );
}

#[test]
fn ambiguous_address_pair_or_hidden_translation_never_issues_a_kill() {
    let blocked = row(
        1,
        "en0 tcp 192.0.2.2:54000 -> 198.51.100.1:443 ESTABLISHED:ESTABLISHED",
    );
    for other in [
        "en0 tcp 192.0.2.2:54001 -> 198.51.100.1:33 ESTABLISHED:ESTABLISHED",
        "en0 tcp 192.0.2.2:54001 -> 203.0.113.1:443 ESTABLISHED:ESTABLISHED",
        "en0 tcp 198.51.100.1:33 <- 203.0.113.1:443 ESTABLISHED:ESTABLISHED",
    ] {
        let content = format!("{blocked}{}", row(2, other));
        assert_eq!(
            run_steps([states(&content)], |run| clear_states(&policy(false), run)),
            Err(StateError::AmbiguousSelector)
        );
    }
    let translated = row(
        1,
        "en0 tcp 192.0.2.3:54000 -> 192.0.2.2:54001 -> 198.51.100.1:443 ESTABLISHED:ESTABLISHED",
    );
    assert_eq!(
        run_steps([states(&translated)], |run| clear_states(
            &policy(false),
            run
        )),
        Err(StateError::TranslatedState)
    );
}

#[test]
fn unrecognized_or_unconfirmed_rows_do_not_certify_protection() {
    let blocked = row(
        1,
        "en0 tcp 192.0.2.2:54000 -> 198.51.100.1:443 ESTABLISHED:ESTABLISHED",
    );
    let malformed = format!("{blocked}en0 tcp unexpected");
    assert_eq!(
        run_steps([states(&malformed)], |run| clear_states(
            &policy(false),
            run
        )),
        Err(StateError::UnrecognizedState)
    );
    for (interface, error) in [
        ("all", StateError::FloatingState),
        ("bridge9", StateError::UnknownInterface),
    ] {
        let content = row(
            1,
            &format!("{interface} tcp 192.0.2.2:54000 -> 198.51.100.1:443 ESTABLISHED:ESTABLISHED"),
        );
        assert_eq!(
            run_steps([states(&content)], |run| clear_states(&policy(false), run)),
            Err(error)
        );
    }
    assert_eq!(
        clear_states(&policy(false), |_| Err::<PfOutput, _>(())),
        Err(StateError::ReadFailed)
    );
    assert_eq!(
        clear_states(&policy(false), |_| Ok::<_, ()>(PfOutput {
            stdout: String::new(),
            stderr: "pfctl: DIOCGETSTATES: Permission denied".to_owned(),
        })),
        Err(StateError::ReadFailed)
    );
}

#[test]
fn replacement_multiple_kills_and_residual_states_are_failures() {
    let head = "en0 tcp 192.0.2.2:54000 -> 198.51.100.1:443 ESTABLISHED:ESTABLISHED";
    let original = row(1, head);
    let replacement = row(2, head);
    assert_eq!(
        run_steps([states(&original), states(&replacement)], |run| {
            clear_states(&policy(false), run)
        }),
        Err(StateError::StateChanged)
    );
    assert_eq!(
        run_steps(
            [
                states(&original),
                states(&original),
                kill("en0", "192.0.2.2", "198.51.100.1", 2),
            ],
            |run| clear_states(&policy(false), run)
        ),
        Err(StateError::DeleteFailed)
    );
    assert_eq!(
        run_steps(
            [
                states(&original),
                states(&original),
                kill("en0", "192.0.2.2", "198.51.100.1", 0),
                states(&original),
            ],
            |run| clear_states(&policy(false), run)
        ),
        Err(StateError::BlockedStateRemains)
    );
}
