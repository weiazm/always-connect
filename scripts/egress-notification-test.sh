#!/bin/bash
# Runs the App's Notifier with an in-memory notification center and action sink.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d /tmp/ac-egress-notice.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# The harness supplies the system types, including the response that macOS
# normally builds after the user selects an action.
sed 's/^import UserNotifications$/import Foundation/' "$ROOT/Sources/App/Notifier.swift" > "$WORK/Notifier.swift"
swiftc -parse-as-library "$WORK/Notifier.swift" \
    "$ROOT/Sources/Shared/EgressProtection.swift" "$ROOT/core/scripts/EgressNotificationHarness.swift" \
    -o "$WORK/harness"
"$WORK/harness"
