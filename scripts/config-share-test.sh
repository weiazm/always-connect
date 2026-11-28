#!/bin/bash
# Configuration sharing end to end (DESIGN.md §七十五): the App's export,
# import, write and undo code with the Rust core, in a settings suite of
# its own, an in-memory keychain and a stand-in background service.
# Touches no real settings, keychain or network.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
(cd "$ROOT/core" && cargo build --release --quiet)
sed 's/group\.com\.alwaysconnect\.app/com.example.alwaysconnect.sharetest/g' "$ROOT/Sources/Shared/Models.swift" > "$WORK/Models.swift"
SHARED=()
for f in "$ROOT"/Sources/Shared/*.swift; do [ "$(basename "$f")" = Models.swift ] || SHARED+=("$f"); done
swiftc -O -parse-as-library "$ROOT/Sources/App/ConfigShare.swift" "$ROOT/Sources/App/ListRules.swift" "$ROOT/Sources/App/DirectSites.swift" \
    "$ROOT/Sources/App/ProxyRoutes.swift" "$ROOT/Sources/App/KeychainStore.swift" "$ROOT/Sources/App/OnDemand.swift" \
    "$ROOT/Sources/App/ProfileStore.swift" "$ROOT/Sources/App/DropHistory.swift" "$ROOT/Sources/App/CiscoProfiles.swift" \
    "$WORK/Models.swift" "${SHARED[@]}" "$ROOT/core/scripts/ConfigShareTest.swift" "$ROOT/core/target/release/libalwaysconnect_core.a" \
    -o "$WORK/test" 2>&1 | grep -v "built for newer" || true
ALWAYSCONNECT_GEODATA="$ROOT/core/scripts/fixtures/geodata" "$WORK/test"
