#!/bin/bash
# Real-pf check for proxied sites (DESIGN.md §六十九): the loopback routes,
# the pf redirect and the listener carry connections to proxied names and
# a written network through a local SOCKS5 and HTTP CONNECT proxy, and UDP
# through the SOCKS5 association; UDP not carried and a stopped listener
# are refused; everything is taken out again.
#
#   (cd core && cargo build --example proxy-redirect-check)
#   sudo scripts/proxy-redirect-test.sh core/target/debug/examples/proxy-redirect-check
#
# Touches only 198.19.128.0/17, 203.0.113.0/24 (ranges never used publicly)
# and loopback.
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 2; }
CHECK="${1:?path to proxy-redirect-check}"
ANCHOR=com.apple/301.AlwaysConnectProxy
cleanup() {
    /sbin/pfctl -a "$ANCHOR" -F nat >/dev/null 2>&1 || true
    /sbin/pfctl -a "$ANCHOR" -F rules >/dev/null 2>&1 || true
    # Only our own route (via 127.0.0.1), never another program's.
    for net in 198.19.128.0/17:198.19.128/17 203.0.113.0/24:203.0.113/24; do
        if /usr/sbin/netstat -rn -f inet | /usr/bin/awk -v n="${net#*:}" '$1==n && $2=="127.0.0.1" {f=1} END {exit !f}'; then
            /sbin/route -n delete -net "${net%%:*}" >/dev/null 2>&1 || true
        fi
    done
}
trap cleanup EXIT
# pf must evaluate com.apple/* (load the system ruleset on an empty runner only).
RULES=$(/sbin/pfctl -s rules 2>/dev/null)
if ! printf '%s\n' "$RULES" | grep -q 'anchor "com.apple/\*"'; then
    [ -z "$RULES" ] || { echo "non-default pf rules present: refusing to replace them" >&2; exit 1; }
    /sbin/pfctl -f /etc/pf.conf >/dev/null 2>&1
fi
"$CHECK"
