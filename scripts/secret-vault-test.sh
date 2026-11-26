#!/bin/bash
# Every secret in one keychain item (DESIGN.md §69.19), with an in-memory
# stand-in for the keychain: no prompt, no real keychain item touched.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
swiftc -O -parse-as-library "$ROOT/Sources/App/KeychainStore.swift" "$ROOT/core/scripts/SecretVaultTest.swift" \
    -o "$WORK/test" 2>&1 | grep -v "built for newer" || true
"$WORK/test"
