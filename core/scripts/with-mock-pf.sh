#!/bin/bash
# The fake tunnel emits a real engine hook. Give that hook a working test
# firewall even when the runner cannot load PF and never touch the host anchor.
set -eu
[ "$(id -u)" != 0 ] || exit 77
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
cp "$(dirname "$0")/fake-pfctl.sh" "$root/pfctl"
ALWAYSCONNECT_TEST_ROOT="$root" "$@"
