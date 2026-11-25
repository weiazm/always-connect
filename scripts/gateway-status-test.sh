#!/bin/bash
# Use the status code from the App, an in-memory XPC peer, and the trust
# transitions recorded by the real certificate relay in the loopback harness.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 "$repo/core/scripts/gateway-status-fixture.py" "$repo" "$work/Client.swift"
swiftc -parse-as-library -module-name GatewayStatusHarness "$work/Client.swift" \
    "$repo/Sources/App/ApprovalPromptTracker.swift" "$repo/Sources/App/StatusLook.swift" "$repo/Sources/App/GlobeIcon.swift" \
    "$repo/Sources/App/GlobeGeometry.swift" "$repo/core/scripts/GatewayStatusHarness.swift" -o "$work/check"
"$work/check" "$1"
